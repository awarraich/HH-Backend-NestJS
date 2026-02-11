import { Controller, Get, Param, UseGuards, HttpCode, HttpStatus } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import { OrganizationType } from '../entities/organization-type.entity';

@Controller('v1/api/organization-types')
@UseGuards(JwtAuthGuard)
export class OrganizationTypesController {
  constructor(
    @InjectRepository(OrganizationType)
    private organizationTypeRepository: Repository<OrganizationType>,
  ) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll() {
    const types = await this.organizationTypeRepository.find({
      order: { name: 'ASC' },
    });

    return SuccessHelper.createSuccessResponse(
      types.map((type) => ({
        id: type.id,
        name: type.name,
        created_at: type.created_at,
      })),
    );
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async findOne(@Param('id') id: string) {
    const type = await this.organizationTypeRepository.findOne({
      where: { id: parseInt(id, 10) },
    });

    if (!type) {
      return SuccessHelper.createSuccessResponse(null);
    }

    return SuccessHelper.createSuccessResponse({
      id: type.id,
      name: type.name,
      created_at: type.created_at,
    });
  }
}

