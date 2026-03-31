import {
  Controller,
  Post,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
  Req,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { LoggedInUser } from '../../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../../common/interfaces/user-with-roles.interface';
import { EmployeesService } from '../services/employees.service';
import { CreateExternalEmployeeDto } from '../dto/create-external-employee.dto';

@Controller('v1/api/employees/external')
@UseGuards(JwtAuthGuard)
export class ExternalEmployeesController {
  constructor(private readonly employeesService: EmployeesService) {}

  private getIpAddress(request: FastifyRequest): string {
    const forwarded = request.headers['x-forwarded-for'];
    if (forwarded) {
      return Array.isArray(forwarded) ? forwarded[0] : forwarded.split(',')[0];
    }
    return request.ip || request.socket.remoteAddress || 'unknown';
  }

  private getUserAgent(request: FastifyRequest): string {
    return request.headers['user-agent'] || 'unknown';
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Body() dto: CreateExternalEmployeeDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);
    const result = await this.employeesService.createExternal(
      dto,
      user.userId,
      ipAddress,
      userAgent,
    );
    return SuccessHelper.createSuccessResponse(
      result,
      'External employee created. An email with temporary password has been sent.',
    );
  }
}
