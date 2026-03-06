import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ProviderRole } from '../entities/provider-role.entity';

@Injectable()
export class ProviderRolesService {
  constructor(
    @InjectRepository(ProviderRole)
    private readonly providerRoleRepository: Repository<ProviderRole>,
  ) {}

  /**
   * Returns all provider roles (e.g. Sitter, RC, LN) for reference/dropdowns.
   */
  async findAll(): Promise<ProviderRole[]> {
    return this.providerRoleRepository.find({
      order: { code: 'ASC' },
    });
  }
}
