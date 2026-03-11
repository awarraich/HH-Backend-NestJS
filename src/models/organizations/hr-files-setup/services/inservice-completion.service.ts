import {
  Injectable,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In } from 'typeorm';
import { InserviceCompletion } from '../entities/inservice-completion.entity';
import { InserviceQuizAttempt } from '../entities/inservice-quiz-attempt.entity';
import { InserviceTraining } from '../entities/inservice-training.entity';
import { EmployeeRequirementTag } from '../entities/employee-requirement-tag.entity';
import { RequirementInserviceTraining } from '../entities/requirement-inservice-training.entity';

export interface InserviceCompletionMapEntry {
  progress_percent: number;
  completed_at: Date | null;
  expiration_at: Date | null;
  last_quiz_score_percent: number | null;
  quiz_attempts_count: number;
}

export type InserviceTrainingStatus =
  | 'not_started'
  | 'in_progress'
  | 'completed'
  | 'expired';

@Injectable()
export class InserviceCompletionService {
  constructor(
    @InjectRepository(InserviceCompletion)
    private readonly completionRepository: Repository<InserviceCompletion>,
    @InjectRepository(InserviceQuizAttempt)
    private readonly quizAttemptRepository: Repository<InserviceQuizAttempt>,
    @InjectRepository(InserviceTraining)
    private readonly inserviceTrainingRepository: Repository<InserviceTraining>,
    @InjectRepository(EmployeeRequirementTag)
    private readonly employeeRequirementTagRepository: Repository<EmployeeRequirementTag>,
    @InjectRepository(RequirementInserviceTraining)
    private readonly requirementInserviceTrainingRepository: Repository<RequirementInserviceTraining>,
  ) {}

  /**
   * Returns the set of inservice training IDs the employee is allowed to access
   * (via their requirement tags) in the given organization.
   */
  private async getAllowedInserviceIdsForEmployee(
    organizationId: string,
    employeeId: string,
  ): Promise<Set<string>> {
    const employeeTags = await this.employeeRequirementTagRepository.find({
      where: { employee_id: employeeId },
      select: ['requirement_tag_id'],
    });
    const tagIds = employeeTags.map((t) => t.requirement_tag_id);
    if (tagIds.length === 0) return new Set();

    const links = await this.requirementInserviceTrainingRepository.find({
      where: { requirement_tag_id: In(tagIds) },
      select: ['inservice_training_id'],
    });
    const inserviceIds = [...new Set(links.map((l) => l.inservice_training_id))];
    if (inserviceIds.length === 0) return new Set();

    const trainings = await this.inserviceTrainingRepository.find({
      where: {
        id: In(inserviceIds),
        organization_id: organizationId,
        is_active: true,
      },
      select: ['id'],
    });
    return new Set(trainings.map((t) => t.id));
  }

  /**
   * Ensures the employee has access to the inservice training (via requirement tags).
   * Throws ForbiddenException if not allowed, NotFoundException if training not found.
   */
  private async ensureEmployeeHasAccessToInservice(
    organizationId: string,
    employeeId: string,
    inserviceTrainingId: string,
  ): Promise<InserviceTraining> {
    const training = await this.inserviceTrainingRepository.findOne({
      where: {
        id: inserviceTrainingId,
        organization_id: organizationId,
        is_active: true,
      },
    });
    if (!training) {
      throw new NotFoundException(
        `Inservice training with ID ${inserviceTrainingId} not found.`,
      );
    }

    const allowedIds = await this.getAllowedInserviceIdsForEmployee(
      organizationId,
      employeeId,
    );
    if (!allowedIds.has(inserviceTrainingId)) {
      throw new ForbiddenException(
        'You do not have access to this inservice training.',
      );
    }
    return training;
  }

  /**
   * Returns a map of inservice_training_id -> completion data for list enrichment.
   */
  async getCompletionMap(
    employeeId: string,
    inserviceTrainingIds: string[],
  ): Promise<Map<string, InserviceCompletionMapEntry>> {
    if (inserviceTrainingIds.length === 0) {
      return new Map();
    }

    const completions = await this.completionRepository.find({
      where: {
        employee_id: employeeId,
        inservice_training_id: In(inserviceTrainingIds),
      },
    });

    const map = new Map<string, InserviceCompletionMapEntry>();
    for (const c of completions) {
      map.set(c.inservice_training_id, {
        progress_percent: c.progress_percent,
        completed_at: c.completed_at,
        expiration_at: c.expiration_at,
        last_quiz_score_percent: c.last_quiz_score_percent,
        quiz_attempts_count: c.quiz_attempts_count,
      });
    }
    for (const id of inserviceTrainingIds) {
      if (!map.has(id)) {
        map.set(id, {
          progress_percent: 0,
          completed_at: null,
          expiration_at: null,
          last_quiz_score_percent: null,
          quiz_attempts_count: 0,
        });
      }
    }
    return map;
  }

  /**
   * Derives status from completion and current time.
   */
  getStatus(
    entry: InserviceCompletionMapEntry,
    hasQuiz: boolean,
  ): InserviceTrainingStatus {
    const now = new Date();
    if (entry.completed_at) {
      if (entry.expiration_at && entry.expiration_at < now) {
        return 'expired';
      }
      return 'completed';
    }
    if (entry.progress_percent > 0) return 'in_progress';
    return 'not_started';
  }

  async updateProgress(
    organizationId: string,
    employeeId: string,
    inserviceTrainingId: string,
    progressPercent: number,
  ): Promise<InserviceCompletion> {
    await this.ensureEmployeeHasAccessToInservice(
      organizationId,
      employeeId,
      inserviceTrainingId,
    );

    const clamped = Math.min(100, Math.max(0, Math.round(progressPercent)));
    let completion = await this.completionRepository.findOne({
      where: {
        employee_id: employeeId,
        inservice_training_id: inserviceTrainingId,
      },
    });

    if (!completion) {
      completion = this.completionRepository.create({
        employee_id: employeeId,
        inservice_training_id: inserviceTrainingId,
        progress_percent: clamped,
      });
    } else {
      completion.progress_percent = clamped;
    }
    return this.completionRepository.save(completion);
  }

  async markComplete(
    organizationId: string,
    employeeId: string,
    inserviceTrainingId: string,
  ): Promise<InserviceCompletion> {
    const training = await this.ensureEmployeeHasAccessToInservice(
      organizationId,
      employeeId,
      inserviceTrainingId,
    );

    const now = new Date();
    let expirationAt: Date | null = null;
    if (training.expiry_months != null && training.expiry_months > 0) {
      const exp = new Date(now);
      exp.setMonth(exp.getMonth() + training.expiry_months);
      expirationAt = exp;
    }

    let completion = await this.completionRepository.findOne({
      where: {
        employee_id: employeeId,
        inservice_training_id: inserviceTrainingId,
      },
    });

    if (!completion) {
      completion = this.completionRepository.create({
        employee_id: employeeId,
        inservice_training_id: inserviceTrainingId,
        progress_percent: 100,
        completed_at: now,
        expiration_at: expirationAt,
      });
    } else {
      completion.progress_percent = 100;
      completion.completed_at = now;
      completion.expiration_at = expirationAt;
    }
    return this.completionRepository.save(completion);
  }

  async recordQuizAttempt(
    organizationId: string,
    employeeId: string,
    inserviceTrainingId: string,
    scorePercent: number,
    passed: boolean,
  ): Promise<{ attempt: InserviceQuizAttempt; completion: InserviceCompletion }> {
    const training = await this.ensureEmployeeHasAccessToInservice(
      organizationId,
      employeeId,
      inserviceTrainingId,
    );

    const attempt = this.quizAttemptRepository.create({
      employee_id: employeeId,
      inservice_training_id: inserviceTrainingId,
      score_percent: Math.min(100, Math.max(0, Math.round(scorePercent))),
      passed,
    });
    const savedAttempt = await this.quizAttemptRepository.save(attempt);

    let completion = await this.completionRepository.findOne({
      where: {
        employee_id: employeeId,
        inservice_training_id: inserviceTrainingId,
      },
    });

    if (!completion) {
      completion = this.completionRepository.create({
        employee_id: employeeId,
        inservice_training_id: inserviceTrainingId,
        progress_percent: 0,
        last_quiz_score_percent: savedAttempt.score_percent,
        quiz_attempts_count: 1,
      });
    } else {
      completion.last_quiz_score_percent = savedAttempt.score_percent;
      completion.quiz_attempts_count = completion.quiz_attempts_count + 1;
    }

    if (passed) {
      const now = new Date();
      completion.completed_at = now;
      completion.progress_percent = 100;
      if (training.expiry_months != null && training.expiry_months > 0) {
        const exp = new Date(now);
        exp.setMonth(exp.getMonth() + training.expiry_months);
        completion.expiration_at = exp;
      } else {
        completion.expiration_at = null;
      }
    }

    const savedCompletion = await this.completionRepository.save(completion);
    return { attempt: savedAttempt, completion: savedCompletion };
  }
}
