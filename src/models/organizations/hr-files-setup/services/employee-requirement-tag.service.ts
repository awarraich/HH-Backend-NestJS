import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In, EntityManager } from 'typeorm';
import { EmployeeRequirementTag } from '../entities/employee-requirement-tag.entity';
import { RequirementTag } from '../entities/requirement-tag.entity';

@Injectable()
export class EmployeeRequirementTagService {
  constructor(
    @InjectRepository(EmployeeRequirementTag)
    private readonly employeeRequirementTagRepository: Repository<EmployeeRequirementTag>,
    @InjectRepository(RequirementTag)
    private readonly requirementTagRepository: Repository<RequirementTag>,
  ) {}

  async assignToEmployee(
    employeeId: string,
    organizationId: string,
    tagIds: string[],
    manager?: EntityManager,
  ): Promise<void> {
    const uniqueTagIds = tagIds?.length ? [...new Set(tagIds)] : [];
    if (uniqueTagIds.length === 0) return;

    const repo = manager
      ? manager.getRepository(EmployeeRequirementTag)
      : this.employeeRequirementTagRepository;
    const tagRepo = manager
      ? manager.getRepository(RequirementTag)
      : this.requirementTagRepository;

    const tags = await tagRepo.find({
      where: { id: In(uniqueTagIds), organization_id: organizationId },
      select: ['id'],
    });
    if (tags.length !== uniqueTagIds.length) {
      throw new BadRequestException(
        'One or more requirement tag IDs are invalid or do not belong to this organization.',
      );
    }

    const existing = await repo.find({
      where: { employee_id: employeeId },
      select: ['requirement_tag_id'],
    });
    const existingTagIds = new Set(existing.map((e) => e.requirement_tag_id));
    const toInsert = uniqueTagIds.filter((id) => !existingTagIds.has(id));
    if (toInsert.length === 0) return;

    const entities = toInsert.map((requirement_tag_id) =>
      repo.create({ employee_id: employeeId, requirement_tag_id }),
    );
    await repo.save(entities);
  }
}
