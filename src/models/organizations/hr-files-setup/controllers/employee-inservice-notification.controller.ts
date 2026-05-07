import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { IsNotEmpty, IsOptional, IsString, IsUUID, MaxLength } from 'class-validator';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { EmployeeDocumentAccessGuard } from '../../../../common/guards/employee-document-access.guard';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { InserviceNotificationService } from '../services/inservice-notification.service';
import { InserviceAiAgentService } from '../services/inservice-ai-agent.service';

class AskInserviceAgentDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(1000)
  question!: string;
}

class NotifyInserviceDto {
  @IsOptional()
  @IsUUID()
  training_id?: string;
}

@Controller('v1/api/organizations/:organizationId/employees/:employeeId/inservice')
@UseGuards(JwtAuthGuard, EmployeeDocumentAccessGuard)
export class EmployeeInserviceNotificationController {
  constructor(
    private readonly notificationService: InserviceNotificationService,
    private readonly aiAgentService: InserviceAiAgentService,
  ) {}

  /**
   * Returns the employee's full in-service compliance report — required
   * trainings, current completions, and every gap (missing / expired /
   * expiring within 30 days / in progress). Powers both the "Notify User"
   * button preview and the auto-opening AI agent.
   */
  @Get('status')
  @HttpCode(HttpStatus.OK)
  async getStatus(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
  ) {
    const report = await this.notificationService.buildReport(organizationId, employeeId);
    return SuccessHelper.createSuccessResponse(report, 'In-service status report generated');
  }

  /**
   * Sends an email reminder to the employee listing every gap. Also
   * registers the employee in the daily expiry sweep (which is global —
   * it scans all employees automatically — so this just fires the
   * immediate notification that the daily cron would also send).
   */
  @Post('notify')
  @HttpCode(HttpStatus.OK)
  async notify(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    // Body is optional — header "Notify User" sends none, per-row sends {training_id}.
    @Body() dto?: NotifyInserviceDto,
  ) {
    const result = await this.notificationService.notifyEmployee(organizationId, employeeId, {
      trainingId: dto?.training_id,
    });
    return SuccessHelper.createSuccessResponse(
      {
        email_sent: result.emailSent,
        skip_reason: result.reason ?? null,
        report: result.report,
      },
      result.emailSent
        ? 'Notification email sent to the employee'
        : 'Could not send notification — see skip_reason',
    );
  }

  /** Frees-form chat with the AI agent grounded in the gap report. */
  @Post('ai-ask')
  @HttpCode(HttpStatus.OK)
  async ask(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @Body() dto: AskInserviceAgentDto,
  ) {
    const result = await this.aiAgentService.ask(organizationId, employeeId, dto.question);
    return SuccessHelper.createSuccessResponse(result, 'AI agent response');
  }
}
