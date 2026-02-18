import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  Req,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { LoggedInUser } from '../../../common/decorators/requests/logged-in-user.decorator';
import type { UserWithRolesInterface } from '../../../common/interfaces/user-with-roles.interface';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import { MedicationsService } from './medications.service';
import { CreateMedicationDto } from './dto/create-medication.dto';
import { UpdateMedicationDto } from './dto/update-medication.dto';
import { UpdateMedicationInventoryDto } from './dto/update-medication-inventory.dto';
import { MarkMedicationTakenDto } from './dto/mark-medication-taken.dto';

@Controller('v1/api/patients/me/medications')
@UseGuards(JwtAuthGuard)
export class MedicationsController {
  constructor(private readonly medicationsService: MedicationsService) {}

  private getIpAddress(request: FastifyRequest): string {
    const forwarded = request.headers['x-forwarded-for'];
    if (forwarded) {
      return Array.isArray(forwarded) ? forwarded[0] : forwarded.split(',')[0];
    }
    return request.ip ?? (request.socket as any)?.remoteAddress ?? 'unknown';
  }

  private getUserAgent(request: FastifyRequest): string {
    return (request.headers['user-agent'] as string) ?? 'unknown';
  }

  @Get()
  @HttpCode(HttpStatus.OK)
  async list(
    @LoggedInUser() user: UserWithRolesInterface,
    @Query('date') date: string | undefined,
    @Req() request: FastifyRequest,
  ) {
    const auditContext = {
      userId: user.userId,
      ipAddress: this.getIpAddress(request),
      userAgent: this.getUserAgent(request),
    };
    const data = await this.medicationsService.findAll(
      user.userId,
      date,
      auditContext,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @LoggedInUser() user: UserWithRolesInterface,
    @Body() dto: CreateMedicationDto,
    @Req() request: FastifyRequest,
  ) {
    const auditContext = {
      userId: user.userId,
      ipAddress: this.getIpAddress(request),
      userAgent: this.getUserAgent(request),
    };
    const data = await this.medicationsService.create(
      user.userId,
      dto,
      auditContext,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post(':medicationId/taken')
  @HttpCode(HttpStatus.OK)
  async markAsTaken(
    @LoggedInUser() user: UserWithRolesInterface,
    @Param('medicationId') medicationId: string,
    @Body() dto: MarkMedicationTakenDto,
    @Req() request: FastifyRequest,
  ) {
    const auditContext = {
      userId: user.userId,
      ipAddress: this.getIpAddress(request),
      userAgent: this.getUserAgent(request),
    };
    const data = await this.medicationsService.markAsTaken(
      user.userId,
      medicationId,
      dto,
      auditContext,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Patch(':medicationId/inventory')
  @HttpCode(HttpStatus.OK)
  async updateInventory(
    @LoggedInUser() user: UserWithRolesInterface,
    @Param('medicationId') medicationId: string,
    @Body() dto: UpdateMedicationInventoryDto,
    @Req() request: FastifyRequest,
  ) {
    const auditContext = {
      userId: user.userId,
      ipAddress: this.getIpAddress(request),
      userAgent: this.getUserAgent(request),
    };
    const data = await this.medicationsService.updateInventory(
      user.userId,
      medicationId,
      dto,
      auditContext,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Patch(':medicationId')
  @HttpCode(HttpStatus.OK)
  async update(
    @LoggedInUser() user: UserWithRolesInterface,
    @Param('medicationId') medicationId: string,
    @Body() dto: UpdateMedicationDto,
    @Req() request: FastifyRequest,
  ) {
    const auditContext = {
      userId: user.userId,
      ipAddress: this.getIpAddress(request),
      userAgent: this.getUserAgent(request),
    };
    const data = await this.medicationsService.update(
      user.userId,
      medicationId,
      dto,
      auditContext,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Delete(':medicationId')
  @HttpCode(HttpStatus.OK)
  async remove(
    @LoggedInUser() user: UserWithRolesInterface,
    @Param('medicationId') medicationId: string,
    @Req() request: FastifyRequest,
  ) {
    const auditContext = {
      userId: user.userId,
      ipAddress: this.getIpAddress(request),
      userAgent: this.getUserAgent(request),
    };
    await this.medicationsService.remove(
      user.userId,
      medicationId,
      auditContext,
    );
    return SuccessHelper.createSuccessResponse(
      { id: medicationId, deleted: true },
      'Medication removed',
    );
  }
}
