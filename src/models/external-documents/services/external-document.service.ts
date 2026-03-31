import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CompetencyTemplate } from '../../organizations/document-workflow/entities/competency-template.entity';
import { Employee } from '../../employees/entities/employee.entity';
import { User } from '../../../authentication/entities/user.entity';
import { DocumentFieldValue } from '../entities/document-field-value.entity';
import { SubmitExternalFieldsDto } from '../dto/submit-external-fields.dto';

@Injectable()
export class ExternalDocumentService {
  constructor(
    @InjectRepository(CompetencyTemplate)
    private readonly templateRepo: Repository<CompetencyTemplate>,
    @InjectRepository(Employee)
    private readonly employeeRepo: Repository<Employee>,
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
    @InjectRepository(DocumentFieldValue)
    private readonly fieldValueRepo: Repository<DocumentFieldValue>,
  ) {}

  /**
   * Validate that the user exists and is an external employee (no organization).
   */
  private async validateExternalUser(userId: string): Promise<User> {
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const employee = await this.employeeRepo.findOne({ where: { user_id: userId } });
    if (!employee) {
      throw new NotFoundException('No employee record found for this user');
    }
    if (employee.organization_id !== null) {
      throw new ForbiddenException('This endpoint is only for external employees');
    }

    return user;
  }

  /**
   * Get the set of field IDs assigned to a given user within a template's document_fields.
   */
  private getAssignedFieldIds(
    documentFields: Record<string, any>[],
    userId: string,
  ): Set<string> {
    const ids = new Set<string>();
    for (const field of documentFields) {
      if (field.assignedEmployeeId === userId) {
        ids.add(field.id);
      }
    }
    return ids;
  }

  /**
   * GET /v1/api/documents/external/:userId
   *
   * Find all templates where at least one document_field has assignedEmployeeId matching this user.
   * Return full template fields with isEditable flag + any previously saved values.
   */
  async getTemplatesForUser(userId: string) {
    await this.validateExternalUser(userId);

    // Query templates where document_fields JSONB array contains an element
    // with assignedEmployeeId matching the user ID
    const templates = await this.templateRepo
      .createQueryBuilder('t')
      .where(
        `t.document_fields @> :pattern::jsonb`,
        { pattern: JSON.stringify([{ assignedEmployeeId: userId }]) },
      )
      .orderBy('t.updated_at', 'DESC')
      .getMany();

    if (!templates.length) {
      return [];
    }

    // Load existing field values for this user across all matched templates
    const templateIds = templates.map((t) => t.id);
    const existingValues = await this.fieldValueRepo
      .createQueryBuilder('fv')
      .where('fv.template_id IN (:...templateIds)', { templateIds })
      .andWhere('fv.user_id = :userId', { userId })
      .getMany();

    // Index saved values by template_id + field_id
    const valueMap = new Map<string, any>();
    for (const fv of existingValues) {
      valueMap.set(`${fv.template_id}:${fv.field_id}`, fv.value);
    }

    return templates.map((template) => {
      const assignedFieldIds = this.getAssignedFieldIds(
        template.document_fields,
        userId,
      );

      const fields = template.document_fields.map((field: Record<string, any>) => {
        const isEditable = assignedFieldIds.has(field.id);
        const savedValue = valueMap.get(`${template.id}:${field.id}`);
        return {
          ...field,
          isEditable,
          ...(savedValue !== undefined ? { savedValue } : {}),
        };
      });

      return {
        template_id: template.id,
        name: template.name,
        description: template.description,
        pdfUrl: template.pdf_file_key
          ? `/v1/api/organizations/${template.organization_id}/document-workflow/templates/${template.id}/pdf/view`
          : null,
        fields,
      };
    });
  }

  /**
   * POST /v1/api/documents/:templateId/external-submit
   *
   * Submit field values for an external employee (by user ID).
   * Only fields with assignedEmployeeId matching the user are accepted.
   * Values are stored in document_field_values (template is never mutated).
   */
  async submitFields(templateId: string, dto: SubmitExternalFieldsDto) {
    await this.validateExternalUser(dto.userId);

    const template = await this.templateRepo.findOne({ where: { id: templateId } });
    if (!template) {
      throw new NotFoundException('Template not found');
    }

    // Determine which field IDs this user is allowed to fill
    const assignedFieldIds = this.getAssignedFieldIds(
      template.document_fields,
      dto.userId,
    );

    if (assignedFieldIds.size === 0) {
      throw new ForbiddenException('No fields are assigned to this user on this template');
    }

    // Validate all submitted fields are allowed
    const rejectedFields: string[] = [];
    for (const item of dto.fields) {
      if (!assignedFieldIds.has(item.fieldId)) {
        rejectedFields.push(item.fieldId);
      }
    }
    if (rejectedFields.length > 0) {
      throw new BadRequestException(
        `You are not authorized to fill these fields: ${rejectedFields.join(', ')}`,
      );
    }

    // Upsert each field value
    const saved: DocumentFieldValue[] = [];
    for (const item of dto.fields) {
      const existing = await this.fieldValueRepo.findOne({
        where: {
          template_id: templateId,
          field_id: item.fieldId,
          user_id: dto.userId,
        },
      });

      if (existing) {
        existing.value = item.value;
        saved.push(await this.fieldValueRepo.save(existing));
      } else {
        saved.push(
          await this.fieldValueRepo.save(
            this.fieldValueRepo.create({
              template_id: templateId,
              field_id: item.fieldId,
              user_id: dto.userId,
              value: item.value,
            }),
          ),
        );
      }
    }

    return saved.map((fv) => ({
      id: fv.id,
      template_id: fv.template_id,
      field_id: fv.field_id,
      user_id: fv.user_id,
      value: fv.value,
      created_at: fv.created_at,
      updated_at: fv.updated_at,
    }));
  }
}
