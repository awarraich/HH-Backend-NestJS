import {
  Injectable,
  NotFoundException,
  ConflictException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, IsNull } from 'typeorm';
import { DocumentWorkflowRole } from '../entities/document-workflow-role.entity';
import { CreateWorkflowRoleDto } from '../dto/create-workflow-role.dto';
import { UpdateWorkflowRoleDto } from '../dto/update-workflow-role.dto';

@Injectable()
export class WorkflowRolesService {
  constructor(
    @InjectRepository(DocumentWorkflowRole)
    private readonly repo: Repository<DocumentWorkflowRole>,
  ) {}

  /**
   * Returns default (system) roles + organization-specific roles.
   */
  async findAll(orgId: string) {
    return this.repo
      .createQueryBuilder('r')
      .where('r.organization_id = :orgId', { orgId })
      .orWhere('r.is_default = true')
      .orderBy('r.is_default', 'DESC')
      .addOrderBy('r.name', 'ASC')
      .getMany();
  }

  async findOne(orgId: string, id: string) {
    // Allow finding both org-specific and default roles
    const role = await this.repo
      .createQueryBuilder('r')
      .where('r.id = :id', { id })
      .andWhere('(r.organization_id = :orgId OR r.is_default = true)', { orgId })
      .getOne();
    if (!role) throw new NotFoundException('Workflow role not found');
    return role;
  }

  async create(orgId: string, dto: CreateWorkflowRoleDto) {
    const existing = await this.repo.findOne({
      where: { organization_id: orgId, name: dto.name },
    });
    if (existing) {
      throw new ConflictException(`Role "${dto.name}" already exists in this organization`);
    }

    return this.repo.save(
      this.repo.create({
        organization_id: orgId,
        name: dto.name,
        description: dto.description ?? null,
        is_default: false,
      }),
    );
  }

  async update(orgId: string, id: string, dto: UpdateWorkflowRoleDto) {
    const role = await this.findOne(orgId, id);

    if (role.is_default) {
      throw new ForbiddenException('Default system roles cannot be modified');
    }

    if (dto.name !== undefined && dto.name !== role.name) {
      const existing = await this.repo.findOne({
        where: { organization_id: orgId, name: dto.name },
      });
      if (existing) {
        throw new ConflictException(`Role "${dto.name}" already exists in this organization`);
      }
      role.name = dto.name;
    }
    if (dto.description !== undefined) role.description = dto.description;

    return this.repo.save(role);
  }

  async delete(orgId: string, id: string) {
    const role = await this.findOne(orgId, id);

    if (role.is_default) {
      throw new ForbiddenException('Default system roles cannot be deleted');
    }

    await this.repo.remove(role);
  }
}
