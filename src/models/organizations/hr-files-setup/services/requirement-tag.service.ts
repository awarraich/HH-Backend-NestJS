import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In, IsNull } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { RequirementTag } from '../entities/requirement-tag.entity';
import { RequirementDocumentType } from '../entities/requirement-document-type.entity';
import { RequirementInserviceTraining } from '../entities/requirement-inservice-training.entity';
import { HrDocumentType } from '../entities/hr-document-type.entity';
import { InserviceTraining } from '../entities/inservice-training.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CreateRequirementTagDto } from '../dto/create-requirement-tag.dto';
import { UpdateRequirementTagDto } from '../dto/update-requirement-tag.dto';
import { QueryRequirementTagDto } from '../dto/query-requirement-tag.dto';

export interface RequirementTagResponse {
  id: string;
  organization_id: string;
  title: string;
  category: string;
  required_document_type_ids: string[];
  required_inservice_training_ids: string[];
  created_at: Date;
  updated_at: Date;
}

@Injectable()
export class RequirementTagService {
  constructor(
    @InjectRepository(RequirementTag)
    private readonly requirementTagRepository: Repository<RequirementTag>,
    @InjectRepository(RequirementDocumentType)
    private readonly requirementDocumentTypeRepository: Repository<RequirementDocumentType>,
    @InjectRepository(RequirementInserviceTraining)
    private readonly requirementInserviceTrainingRepository: Repository<RequirementInserviceTraining>,
    @InjectRepository(HrDocumentType)
    private readonly hrDocumentTypeRepository: Repository<HrDocumentType>,
    @InjectRepository(InserviceTraining)
    private readonly inserviceTrainingRepository: Repository<InserviceTraining>,
    @InjectRepository(Organization)
    private readonly organizationRepository: Repository<Organization>,
    private readonly organizationRoleService: OrganizationRoleService,
  ) {}

  private async ensureAccess(organizationId: string, userId: string): Promise<void> {
    const canAccess = await this.organizationRoleService.hasAnyRoleInOrganization(
      userId,
      organizationId,
      ['OWNER', 'HR', 'MANAGER'],
    );
    if (!canAccess) {
      throw new ForbiddenException(
        'You do not have permission to manage requirement tags in this organization.',
      );
    }

    const organization = await this.organizationRepository.findOne({
      where: { id: organizationId },
    });
    if (!organization) {
      throw new NotFoundException('Organization not found');
    }
  }

  private toResponse(
    tag: RequirementTag,
    docTypeIds: string[],
    inserviceTrainingIds: string[],
  ): RequirementTagResponse {
    return {
      id: tag.id,
      organization_id: tag.organization_id,
      title: tag.title,
      category: tag.category,
      required_document_type_ids: docTypeIds,
      required_inservice_training_ids: inserviceTrainingIds,
      created_at: tag.created_at,
      updated_at: tag.updated_at,
    };
  }

  async findAll(
    organizationId: string,
    queryDto: QueryRequirementTagDto,
    userId: string,
  ): Promise<{ data: RequirementTagResponse[]; total: number; page: number; limit: number }> {
    await this.ensureAccess(organizationId, userId);

    const { page = 1, limit = 20, category, search } = queryDto;
    const skip = (page - 1) * limit;

    const qb = this.requirementTagRepository
      .createQueryBuilder('rt')
      .where('rt.organization_id = :organizationId', { organizationId });

    if (category !== undefined && category !== '') {
      qb.andWhere('rt.category = :category', { category });
    }
    if (search && search.trim()) {
      qb.andWhere('rt.title ILIKE :search', { search: `%${search.trim()}%` });
    }

    qb.orderBy('rt.created_at', 'DESC');

    const [tags, total] = await qb.skip(skip).take(limit).getManyAndCount();

    const data: RequirementTagResponse[] = [];
    for (const tag of tags) {
      const [docLinks, inserviceLinks] = await Promise.all([
        this.requirementDocumentTypeRepository.find({
          where: { requirement_tag_id: tag.id },
          select: ['document_type_id'],
        }),
        this.requirementInserviceTrainingRepository.find({
          where: { requirement_tag_id: tag.id },
          select: ['inservice_training_id'],
        }),
      ]);
      data.push(
        this.toResponse(
          tag,
          docLinks.map((l) => l.document_type_id),
          inserviceLinks.map((l) => l.inservice_training_id),
        ),
      );
    }

    return { data, total, page, limit };
  }

  async findOne(
    organizationId: string,
    requirementTagId: string,
    userId: string,
  ): Promise<RequirementTagResponse> {
    await this.ensureAccess(organizationId, userId);

    const tag = await this.requirementTagRepository.findOne({
      where: { id: requirementTagId, organization_id: organizationId },
    });
    if (!tag) {
      throw new NotFoundException('Requirement tag not found');
    }

    const [docLinks, inserviceLinks] = await Promise.all([
      this.requirementDocumentTypeRepository.find({
        where: { requirement_tag_id: tag.id },
        select: ['document_type_id'],
      }),
      this.requirementInserviceTrainingRepository.find({
        where: { requirement_tag_id: tag.id },
        select: ['inservice_training_id'],
      }),
    ]);
    return this.toResponse(
      tag,
      docLinks.map((l) => l.document_type_id),
      inserviceLinks.map((l) => l.inservice_training_id),
    );
  }

  async create(
    organizationId: string,
    dto: CreateRequirementTagDto,
    userId: string,
  ): Promise<RequirementTagResponse> {
    await this.ensureAccess(organizationId, userId);

    const documentTypeIds = dto.document_type_ids ?? [];
    const inserviceTrainingIds = dto.inservice_training_ids ?? [];

    if (documentTypeIds.length > 0) {
      const docTypes = await this.hrDocumentTypeRepository.find({
        where: {
          id: In(documentTypeIds),
          organization_id: organizationId,
          employee_id: IsNull(),
        },
        select: ['id'],
      });
      if (docTypes.length !== documentTypeIds.length) {
        throw new BadRequestException(
          'One or more document type IDs are invalid or do not belong to this organization.',
        );
      }
    }

    if (inserviceTrainingIds.length > 0) {
      const inservices = await this.inserviceTrainingRepository.find({
        where: {
          id: In(inserviceTrainingIds),
          organization_id: organizationId,
        },
        select: ['id'],
      });
      if (inservices.length !== inserviceTrainingIds.length) {
        throw new BadRequestException(
          'One or more inservice training IDs are invalid or do not belong to this organization.',
        );
      }
    }

    const tag = this.requirementTagRepository.create({
      organization_id: organizationId,
      title: dto.title,
      category: dto.category,
    });
    const saved = await this.requirementTagRepository.save(tag);

    const linkEntities = documentTypeIds.map((document_type_id) =>
      this.requirementDocumentTypeRepository.create({
        requirement_tag_id: saved.id,
        document_type_id,
      }),
    );
    await this.requirementDocumentTypeRepository.save(linkEntities);

    const inserviceLinkEntities = inserviceTrainingIds.map(
      (inservice_training_id) =>
        this.requirementInserviceTrainingRepository.create({
          requirement_tag_id: saved.id,
          inservice_training_id,
        }),
    );
    await this.requirementInserviceTrainingRepository.save(
      inserviceLinkEntities,
    );

    return this.toResponse(
      saved,
      documentTypeIds,
      inserviceTrainingIds,
    );
  }

  async update(
    organizationId: string,
    requirementTagId: string,
    dto: UpdateRequirementTagDto,
    userId: string,
  ): Promise<RequirementTagResponse> {
    await this.ensureAccess(organizationId, userId);

    const tag = await this.requirementTagRepository.findOne({
      where: { id: requirementTagId, organization_id: organizationId },
    });
    if (!tag) {
      throw new NotFoundException('Requirement tag not found');
    }

    if (dto.title !== undefined) tag.title = dto.title;
    if (dto.category !== undefined) tag.category = dto.category;
    await this.requirementTagRepository.save(tag);

    if (dto.document_type_ids !== undefined) {
      await this.requirementDocumentTypeRepository.delete({
        requirement_tag_id: tag.id,
      });
      const documentTypeIds = dto.document_type_ids;
      if (documentTypeIds.length > 0) {
        const docTypes = await this.hrDocumentTypeRepository.find({
          where: {
            id: In(documentTypeIds),
            organization_id: organizationId,
            employee_id: IsNull(),
          },
          select: ['id'],
        });
        if (docTypes.length !== documentTypeIds.length) {
          throw new BadRequestException(
            'One or more document type IDs are invalid or do not belong to this organization.',
          );
        }
        const linkEntities = documentTypeIds.map((document_type_id) =>
          this.requirementDocumentTypeRepository.create({
            requirement_tag_id: tag.id,
            document_type_id,
          }),
        );
        await this.requirementDocumentTypeRepository.save(linkEntities);
      }
    }

    if (dto.inservice_training_ids !== undefined) {
      await this.requirementInserviceTrainingRepository.delete({
        requirement_tag_id: tag.id,
      });
      const inserviceTrainingIds = dto.inservice_training_ids;
      if (inserviceTrainingIds.length > 0) {
        const inservices = await this.inserviceTrainingRepository.find({
          where: {
            id: In(inserviceTrainingIds),
            organization_id: organizationId,
          },
          select: ['id'],
        });
        if (inservices.length !== inserviceTrainingIds.length) {
          throw new BadRequestException(
            'One or more inservice training IDs are invalid or do not belong to this organization.',
          );
        }
        const inserviceLinkEntities = inserviceTrainingIds.map(
          (inservice_training_id) =>
            this.requirementInserviceTrainingRepository.create({
              requirement_tag_id: tag.id,
              inservice_training_id,
            }),
        );
        await this.requirementInserviceTrainingRepository.save(
          inserviceLinkEntities,
        );
      }
    }

    const [docLinks, inserviceLinks] = await Promise.all([
      this.requirementDocumentTypeRepository.find({
        where: { requirement_tag_id: tag.id },
        select: ['document_type_id'],
      }),
      this.requirementInserviceTrainingRepository.find({
        where: { requirement_tag_id: tag.id },
        select: ['inservice_training_id'],
      }),
    ]);
    return this.toResponse(
      tag,
      docLinks.map((l) => l.document_type_id),
      inserviceLinks.map((l) => l.inservice_training_id),
    );
  }

  async remove(
    organizationId: string,
    requirementTagId: string,
    userId: string,
  ): Promise<void> {
    await this.ensureAccess(organizationId, userId);

    const tag = await this.requirementTagRepository.findOne({
      where: { id: requirementTagId, organization_id: organizationId },
    });
    if (!tag) {
      throw new NotFoundException('Requirement tag not found');
    }

    await this.requirementTagRepository.remove(tag);
  }
}
