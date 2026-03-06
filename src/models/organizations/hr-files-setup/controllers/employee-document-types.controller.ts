import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { EmployeeDocumentTypeAccessGuard } from '../../../../common/guards/employee-document-type-access.guard';
import { LoggedInUser } from '../../../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../../../common/interfaces/user-with-roles.interface';
import { EmployeeDocumentTypeService } from '../services/employee-document-type.service';
import { CreateHrDocumentTypeDto } from '../dto/create-hr-document-type.dto';
import { UpdateHrDocumentTypeDto } from '../dto/update-hr-document-type.dto';

@Controller('v1/api/employees/:employeeId/document-types')
@UseGuards(JwtAuthGuard, EmployeeDocumentTypeAccessGuard)
export class EmployeeDocumentTypesController {
  constructor(
    private readonly employeeDocumentTypeService: EmployeeDocumentTypeService,
  ) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async list(
    @Param('employeeId') employeeId: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const data = await this.employeeDocumentTypeService.listForEmployee(
      employeeId,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('employeeId') employeeId: string,
    @Body() dto: CreateHrDocumentTypeDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.employeeDocumentTypeService.createForEmployee(
      employeeId,
      dto,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(
      result,
      'Document type created successfully',
    );
  }

  @Patch(':id')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('employeeId') employeeId: string,
    @Param('id') id: string,
    @Body() dto: UpdateHrDocumentTypeDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.employeeDocumentTypeService.updateForEmployee(
      employeeId,
      id,
      dto,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(
      result,
      'Document type updated successfully',
    );
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('employeeId') employeeId: string,
    @Param('id') id: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    await this.employeeDocumentTypeService.removeForEmployee(
      employeeId,
      id,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(
      null,
      'Document type deactivated successfully',
    );
  }
}
