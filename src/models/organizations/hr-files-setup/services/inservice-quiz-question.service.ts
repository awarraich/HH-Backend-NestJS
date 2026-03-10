import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { InserviceQuizQuestion } from '../entities/inservice-quiz-question.entity';
import { InserviceTrainingService } from './inservice-training.service';
import { CreateInserviceQuizQuestionDto } from '../dto/create-inservice-quiz-question.dto';
import { UpdateInserviceQuizQuestionDto } from '../dto/update-inservice-quiz-question.dto';

export interface InserviceQuizQuestionResponse {
  id: string;
  inservice_training_id: string;
  sort_order: number;
  question_type: string;
  question_text: string;
  options: string[] | null;
  correct_answer_index: number | null;
  correct_boolean: boolean | null;
  correct_text: string | null;
  sample_answer: string | null;
  left_column: unknown;
  right_column: unknown;
  correct_matches: unknown;
  explanation: string | null;
  created_at: Date;
  updated_at: Date;
}

@Injectable()
export class InserviceQuizQuestionService {
  constructor(
    @InjectRepository(InserviceQuizQuestion)
    private readonly quizQuestionRepository: Repository<InserviceQuizQuestion>,
    private readonly inserviceTrainingService: InserviceTrainingService,
  ) {}

  private toResponse(q: InserviceQuizQuestion): InserviceQuizQuestionResponse {
    return {
      id: q.id,
      inservice_training_id: q.inservice_training_id,
      sort_order: q.sort_order,
      question_type: q.question_type,
      question_text: q.question_text,
      options: q.options,
      correct_answer_index: q.correct_answer_index,
      correct_boolean: q.correct_boolean,
      correct_text: q.correct_text,
      sample_answer: q.sample_answer,
      left_column: q.left_column ?? null,
      right_column: q.right_column ?? null,
      correct_matches: q.correct_matches ?? null,
      explanation: q.explanation,
      created_at: q.created_at,
      updated_at: q.updated_at,
    };
  }

  async findAll(inserviceId: string, userId: string): Promise<InserviceQuizQuestionResponse[]> {
    await this.inserviceTrainingService.ensureInserviceAccess(inserviceId, userId);

    const questions = await this.quizQuestionRepository.find({
      where: { inservice_training_id: inserviceId },
      order: { sort_order: 'ASC', created_at: 'ASC' },
    });

    return questions.map((q) => this.toResponse(q));
  }

  async findOne(
    inserviceId: string,
    questionId: string,
    userId: string,
  ): Promise<InserviceQuizQuestionResponse> {
    await this.inserviceTrainingService.ensureInserviceAccess(inserviceId, userId);

    const question = await this.quizQuestionRepository.findOne({
      where: {
        id: questionId,
        inservice_training_id: inserviceId,
      },
    });

    if (!question) {
      throw new NotFoundException('Quiz question not found');
    }

    return this.toResponse(question);
  }

  async create(
    inserviceId: string,
    dto: CreateInserviceQuizQuestionDto,
    userId: string,
  ): Promise<InserviceQuizQuestionResponse> {
    await this.inserviceTrainingService.ensureInserviceAccess(inserviceId, userId);

    const existingCount = await this.quizQuestionRepository.count({
      where: { inservice_training_id: inserviceId },
    });

    const question = this.quizQuestionRepository.create({
      inservice_training_id: inserviceId,
      sort_order: dto.sort_order ?? 0,
      question_type: dto.question_type,
      question_text: dto.question_text,
      options: dto.options ?? null,
      correct_answer_index: dto.correct_answer_index ?? null,
      correct_boolean: dto.correct_boolean ?? null,
      correct_text: dto.correct_text ?? null,
      sample_answer: dto.sample_answer ?? null,
      left_column: (dto.left_column ?? null) as unknown,
      right_column: (dto.right_column ?? null) as unknown,
      correct_matches: (dto.correct_matches ?? null) as unknown,
      explanation: dto.explanation ?? null,
    } as Partial<InserviceQuizQuestion>);

    const saved = await this.quizQuestionRepository.save(question);

    if (existingCount === 0) {
      await this.inserviceTrainingService.setHasQuiz(inserviceId, true);
    }

    return this.toResponse(saved);
  }

  async update(
    inserviceId: string,
    questionId: string,
    dto: UpdateInserviceQuizQuestionDto,
    userId: string,
  ): Promise<InserviceQuizQuestionResponse> {
    await this.inserviceTrainingService.ensureInserviceAccess(inserviceId, userId);

    const question = await this.quizQuestionRepository.findOne({
      where: {
        id: questionId,
        inservice_training_id: inserviceId,
      },
    });

    if (!question) {
      throw new NotFoundException('Quiz question not found');
    }

    if (dto.question_type !== undefined) question.question_type = dto.question_type;
    if (dto.question_text !== undefined) question.question_text = dto.question_text;
    if (dto.sort_order !== undefined) question.sort_order = dto.sort_order;
    if (dto.options !== undefined) question.options = dto.options;
    if (dto.correct_answer_index !== undefined) {
      question.correct_answer_index = dto.correct_answer_index;
    }
    if (dto.correct_boolean !== undefined) {
      question.correct_boolean = dto.correct_boolean;
    }
    if (dto.correct_text !== undefined) question.correct_text = dto.correct_text;
    if (dto.sample_answer !== undefined) {
      question.sample_answer = dto.sample_answer;
    }
    if (dto.left_column !== undefined) {
      question.left_column = dto.left_column as unknown;
    }
    if (dto.right_column !== undefined) {
      question.right_column = dto.right_column as unknown;
    }
    if (dto.correct_matches !== undefined) {
      question.correct_matches = dto.correct_matches as unknown;
    }
    if (dto.explanation !== undefined) question.explanation = dto.explanation;

    const saved = await this.quizQuestionRepository.save(question);
    return this.toResponse(saved);
  }

  async remove(inserviceId: string, questionId: string, userId: string): Promise<void> {
    await this.inserviceTrainingService.ensureInserviceAccess(inserviceId, userId);

    const question = await this.quizQuestionRepository.findOne({
      where: {
        id: questionId,
        inservice_training_id: inserviceId,
      },
    });

    if (!question) {
      throw new NotFoundException('Quiz question not found');
    }

    await this.quizQuestionRepository.remove(question);

    const remainingCount = await this.quizQuestionRepository.count({
      where: { inservice_training_id: inserviceId },
    });

    if (remainingCount === 0) {
      await this.inserviceTrainingService.setHasQuiz(inserviceId, false);
      await this.inserviceTrainingService.setPassingScore(inserviceId, null);
    }
  }
}
