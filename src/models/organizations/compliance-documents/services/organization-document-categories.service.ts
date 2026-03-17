import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { IsNull, Repository } from 'typeorm';
import { OrganizationDocumentCategory } from '../entities/organization-document-category.entity';
import { OrganizationDocument } from '../entities/organization-document.entity';
import { CreateDocumentCategoryDto } from '../dto/create-document-category.dto';
import { UpdateDocumentCategoryDto } from '../dto/update-document-category.dto';
import { OrganizationDocumentCategorySerializer } from '../serializers/organization-document-category.serializer';

@Injectable()
export class OrganizationDocumentCategoriesService {
  private readonly serializer = new OrganizationDocumentCategorySerializer();

  constructor(
    @InjectRepository(OrganizationDocumentCategory)
    private readonly categoryRepository: Repository<OrganizationDocumentCategory>,
    @InjectRepository(OrganizationDocument)
    private readonly documentRepository: Repository<OrganizationDocument>,
  ) {}

  async findAll(organizationId: string) {
    const categories = await this.categoryRepository.find({
      where: { organization_id: organizationId, is_active: true, deleted_at: IsNull() },
      order: { sort_order: 'ASC', name: 'ASC' },
    });

    const countMap = await this.getDocumentCountMap(organizationId);
    return {
      categories: this.serializer.serializeMany(categories, countMap),
      total: categories.length,
    };
  }

  async findOne(organizationId: string, id: string) {
    const category = await this.categoryRepository.findOne({
      where: { id, organization_id: organizationId, deleted_at: IsNull() },
    });
    if (!category) throw new NotFoundException('Category not found');

    const count = await this.documentRepository.count({
      where: { category_id: id, organization_id: organizationId, deleted_at: IsNull() },
    });
    return this.serializer.serialize(category, count);
  }

  async create(organizationId: string, dto: CreateDocumentCategoryDto, userId: string) {
    const existing = await this.categoryRepository.findOne({
      where: { organization_id: organizationId, name: dto.name, deleted_at: IsNull() },
    });
    if (existing) throw new BadRequestException('A category with this name already exists');

    const category = this.categoryRepository.create({
      organization_id: organizationId,
      name: dto.name,
      description: dto.description ?? null,
      icon: dto.icon ?? null,
      color: dto.color ?? null,
      created_by: userId,
      updated_by: userId,
    });
    const saved = await this.categoryRepository.save(category);
    return this.serializer.serialize(saved, 0);
  }

  async update(organizationId: string, id: string, dto: UpdateDocumentCategoryDto, userId: string) {
    const category = await this.categoryRepository.findOne({
      where: { id, organization_id: organizationId, deleted_at: IsNull() },
    });
    if (!category) throw new NotFoundException('Category not found');

    if (dto.name !== undefined && dto.name !== category.name) {
      const existing = await this.categoryRepository.findOne({
        where: { organization_id: organizationId, name: dto.name, deleted_at: IsNull() },
      });
      if (existing && existing.id !== id) {
        throw new BadRequestException('A category with this name already exists');
      }
    }

    if (dto.name !== undefined) category.name = dto.name;
    if (dto.description !== undefined) category.description = dto.description;
    if (dto.icon !== undefined) category.icon = dto.icon;
    if (dto.color !== undefined) category.color = dto.color;
    if (dto.sort_order !== undefined) category.sort_order = dto.sort_order;
    if (dto.is_active !== undefined) category.is_active = dto.is_active;
    category.updated_by = userId;

    const saved = await this.categoryRepository.save(category);
    const count = await this.documentRepository.count({
      where: { category_id: id, organization_id: organizationId, deleted_at: IsNull() },
    });
    return this.serializer.serialize(saved, count);
  }

  async remove(organizationId: string, id: string, userId: string) {
    const category = await this.categoryRepository.findOne({
      where: { id, organization_id: organizationId, deleted_at: IsNull() },
    });
    if (!category) throw new NotFoundException('Category not found');

    const docCount = await this.documentRepository.count({
      where: { category_id: id, organization_id: organizationId, deleted_at: IsNull() },
    });
    if (docCount > 0) {
      throw new BadRequestException(
        'Cannot delete a category that has documents. Move or delete documents first.',
      );
    }

    category.deleted_at = new Date();
    category.updated_by = userId;
    await this.categoryRepository.save(category);
  }

  private async getDocumentCountMap(organizationId: string): Promise<Map<string, number>> {
    const rows: Array<{ category_id: string; count: string }> = await this.documentRepository
      .createQueryBuilder('doc')
      .select('doc.category_id', 'category_id')
      .addSelect('COUNT(doc.id)', 'count')
      .where('doc.organization_id = :organizationId', { organizationId })
      .andWhere('doc.deleted_at IS NULL')
      .groupBy('doc.category_id')
      .getRawMany();

    const map = new Map<string, number>();
    for (const row of rows) {
      map.set(row.category_id, parseInt(row.count, 10));
    }
    return map;
  }
}
