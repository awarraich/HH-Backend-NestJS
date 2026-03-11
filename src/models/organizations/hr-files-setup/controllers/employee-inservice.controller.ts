import {
  Controller,
  Patch,
  Post,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { EmployeeDocumentAccessGuard } from '../../../../common/guards/employee-document-access.guard';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { InserviceCompletionService } from '../services/inservice-completion.service';
import { UpdateInserviceCompletionProgressDto } from '../dto/update-inservice-completion-progress.dto';
import { CreateInserviceQuizAttemptDto } from '../dto/create-inservice-quiz-attempt.dto';

@Controller('v1/api/organizations/:organizationId/employees/:employeeId')
@UseGuards(JwtAuthGuard, EmployeeDocumentAccessGuard)
export class EmployeeInserviceController {
  constructor(
    private readonly inserviceCompletionService: InserviceCompletionService,
  ) {}

  @Patch('inservice-completions/:inserviceTrainingId')
  @HttpCode(HttpStatus.OK)
  async updateProgress(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @Param('inserviceTrainingId') inserviceTrainingId: string,
    @Body() dto: UpdateInserviceCompletionProgressDto,
  ) {
    const completion =
      await this.inserviceCompletionService.updateProgress(
        organizationId,
        employeeId,
        inserviceTrainingId,
        dto.progress_percent,
      );
    return SuccessHelper.createSuccessResponse(
      this.serializeCompletion(completion),
      'Progress updated',
    );
  }

  @Post('inservice-completions/:inserviceTrainingId/complete')
  @HttpCode(HttpStatus.OK)
  async markComplete(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @Param('inserviceTrainingId') inserviceTrainingId: string,
  ) {
    const completion =
      await this.inserviceCompletionService.markComplete(
        organizationId,
        employeeId,
        inserviceTrainingId,
      );
    return SuccessHelper.createSuccessResponse(
      this.serializeCompletion(completion),
      'Training marked complete',
    );
  }

  @Post('inservice-trainings/:inserviceTrainingId/quiz-attempts')
  @HttpCode(HttpStatus.CREATED)
  async recordQuizAttempt(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @Param('inserviceTrainingId') inserviceTrainingId: string,
    @Body() dto: CreateInserviceQuizAttemptDto,
  ) {
    const { attempt, completion } =
      await this.inserviceCompletionService.recordQuizAttempt(
        organizationId,
        employeeId,
        inserviceTrainingId,
        dto.score_percent,
        dto.passed,
      );
    return SuccessHelper.createSuccessResponse(
      {
        id: attempt.id,
        employee_id: attempt.employee_id,
        inservice_training_id: attempt.inservice_training_id,
        score_percent: attempt.score_percent,
        passed: attempt.passed,
        created_at: attempt.created_at,
      },
      'Quiz attempt recorded',
    );
  }

  private serializeCompletion(completion: {
    id: string;
    employee_id: string;
    inservice_training_id: string;
    progress_percent: number;
    completed_at: Date | null;
    expiration_at: Date | null;
    last_quiz_score_percent: number | null;
    quiz_attempts_count: number;
    created_at: Date;
    updated_at: Date;
  }) {
    return {
      id: completion.id,
      employee_id: completion.employee_id,
      inservice_training_id: completion.inservice_training_id,
      progress_percent: completion.progress_percent,
      completed_at: completion.completed_at
        ? completion.completed_at.toISOString()
        : null,
      expiration_at: completion.expiration_at
        ? completion.expiration_at.toISOString()
        : null,
      last_quiz_score_percent: completion.last_quiz_score_percent,
      quiz_attempts_count: completion.quiz_attempts_count,
      created_at: completion.created_at,
      updated_at: completion.updated_at,
    };
  }
}
