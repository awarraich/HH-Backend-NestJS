import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { CreditPackagesService } from './credit-packages.service';
import { CreateCreditPackageDto } from './dto/create-credit-package.dto';
import { UpdateCreditPackageDto } from './dto/update-credit-package.dto';
import { QueryCreditPackageDto } from './dto/query-credit-package.dto';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { LoggedInUser } from '../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../common/interfaces/user-with-roles.interface';

@Controller('v1/api/credit-packages')
@UseGuards(JwtAuthGuard)
export class CreditPackagesController {
  constructor(private readonly creditPackagesService: CreditPackagesService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Body() createCreditPackageDto: CreateCreditPackageDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.creditPackagesService.create(
      createCreditPackageDto,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(
      result,
      'Credit package created successfully',
    );
  }

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(@Query() queryDto: QueryCreditPackageDto) {
    const result = await this.creditPackagesService.findAll(queryDto);
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async findOne(@Param('id') id: string) {
    const result = await this.creditPackagesService.findOne(id);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Patch(':id')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('id') id: string,
    @Body() updateCreditPackageDto: UpdateCreditPackageDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.creditPackagesService.update(
      id,
      updateCreditPackageDto,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(
      result,
      'Credit package updated successfully',
    );
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('id') id: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    await this.creditPackagesService.remove(id, user.userId);
    return SuccessHelper.createSuccessResponse(
      null,
      'Credit package deleted successfully',
    );
  }
}

