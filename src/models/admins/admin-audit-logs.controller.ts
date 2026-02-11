import { Controller, Get, Query, UseGuards, HttpCode, HttpStatus } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../common/helpers/responses/success.helper';
import { AuditLogService } from '../../common/services/audit/audit-log.service';
import { AuditLogSerializer } from '../audit/serializers/audit-log.serializer';
import { QueryAuditLogsDto } from './dto/query-audit-logs.dto';

@Controller('v1/api/admin/audit-logs')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('ADMIN')
export class AdminAuditLogsController {
  private readonly auditLogSerializer = new AuditLogSerializer();

  constructor(private readonly auditLogService: AuditLogService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async getAuditLogs(@Query() queryDto: QueryAuditLogsDto) {
    const page = queryDto.page ?? 1;
    const limit = queryDto.limit ?? 20;
    const result = await this.auditLogService.getAuditLogsForAdmin({
      page,
      limit,
      userId: queryDto.userId,
      action: queryDto.action,
      resourceType: queryDto.resourceType,
      fromDate: queryDto.fromDate,
      toDate: queryDto.toDate,
    });
    const data = this.auditLogSerializer.serializeMany(result.logs);
    return SuccessHelper.createPaginatedResponse(data, result.total, result.page, result.limit);
  }
}
