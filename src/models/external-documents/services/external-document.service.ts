import {
  Injectable,
  Logger,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CompetencyTemplate } from '../../organizations/document-workflow/entities/competency-template.entity';
import { DocumentTemplateUserAssignment } from '../../organizations/document-workflow/entities/document-template-user-assignment.entity';
import { User } from '../../../authentication/entities/user.entity';
import { Employee } from '../../employees/entities/employee.entity';
import { OrganizationStaff } from '../../organizations/staff-management/entities/organization-staff.entity';
import { DocumentFieldValue } from '../entities/document-field-value.entity';
import { SubmitExternalFieldsDto } from '../dto/submit-external-fields.dto';

@Injectable()
export class ExternalDocumentService {
  private readonly logger = new Logger(ExternalDocumentService.name);

  constructor(
    @InjectRepository(CompetencyTemplate)
    private readonly templateRepo: Repository<CompetencyTemplate>,
    @InjectRepository(DocumentTemplateUserAssignment)
    private readonly userAssignmentRepo: Repository<DocumentTemplateUserAssignment>,
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
    @InjectRepository(DocumentFieldValue)
    private readonly fieldValueRepo: Repository<DocumentFieldValue>,
    @InjectRepository(Employee)
    private readonly employeeRepo: Repository<Employee>,
    @InjectRepository(OrganizationStaff)
    private readonly orgStaffRepo: Repository<OrganizationStaff>,
  ) {}

  /**
   * Look up the signer's display name and best-available job title for the
   * SignedDocumentInfo audit block. See the matching helper on
   * `OfferLetterAssignmentService.resolveSignerSnapshot` — kept duplicated
   * intentionally so each module owns its own dependencies and we don't
   * pull a job-management import into the legacy doc-workflow service.
   *
   * Title resolution: OrganizationStaff.position_title → staffRole.name →
   * Employee.position_title → null.
   */
  private async resolveSignerSnapshot(
    userId: string,
    organizationId: string | null,
  ): Promise<{ name: string | null; title: string | null }> {
    let name: string | null = null;
    let title: string | null = null;
    try {
      const user = await this.userRepo.findOne({ where: { id: userId } });
      if (user) {
        const composed = `${user.firstName ?? ''} ${user.lastName ?? ''}`.trim();
        name = composed || user.email || null;
      }

      if (organizationId) {
        const staff = await this.orgStaffRepo.findOne({
          where: { user_id: userId, organization_id: organizationId },
          relations: ['staffRole'],
        });
        if (staff) {
          title = staff.position_title ?? staff.staffRole?.name ?? null;
        }

        if (!title) {
          const employee = await this.employeeRepo.findOne({
            where: { user_id: userId, organization_id: organizationId },
          });
          if (employee) {
            title = employee.position_title ?? null;
          }
        }
      }
    } catch (err) {
      this.logger.warn(
        `resolveSignerSnapshot failed for user=${userId} org=${organizationId}: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
    return { name, title };
  }

  private async validateUser(userId: string): Promise<User> {
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  /**
   * Get the set of field IDs assigned to a given role within a template's document_fields.
   */
  private getFieldIdsByRole(
    documentFields: Record<string, any>[],
    roleId: string,
  ): Set<string> {
    const ids = new Set<string>();
    for (const field of documentFields) {
      if (field.assignedRoleId === roleId) {
        ids.add(field.id);
      }
    }
    return ids;
  }

  /**
   * GET /v1/api/documents/my-assignments?userId=xxx
   *
   * Find all templates assigned to this user via document_template_user_assignments.
   * For each template, mark fields as editable based on the role the user was assigned.
   * Load ALL filled values from all users so everyone sees each other's data.
   */
  async getMyAssignments(userId: string) {
    await this.validateUser(userId);

    // Find all assignments for this user (with role info)
    const assignments = await this.userAssignmentRepo.find({
      where: { user_id: userId },
      relations: ['role'],
    });

    if (!assignments.length) {
      return [];
    }

    // Group assignments by template_id → role_ids[]
    const templateRoleMap = new Map<string, string[]>();
    for (const a of assignments) {
      const roles = templateRoleMap.get(a.template_id) ?? [];
      roles.push(a.role_id);
      templateRoleMap.set(a.template_id, roles);
    }

    const templateIds = [...templateRoleMap.keys()];

    // Load templates
    const templates = await this.templateRepo
      .createQueryBuilder('t')
      .whereInIds(templateIds)
      .orderBy('t.updated_at', 'DESC')
      .getMany();

    // Load ALL field values for matched templates (from all users)
    const allValues = await this.fieldValueRepo
      .createQueryBuilder('fv')
      .where('fv.template_id IN (:...templateIds)', { templateIds })
      .getMany();

    const valueMap = new Map<
      string,
      { value: any; user_id: string; signature_audit: Record<string, unknown> | null }
    >();
    for (const fv of allValues) {
      valueMap.set(`${fv.template_id}:${fv.field_id}`, {
        value: fv.value,
        user_id: fv.user_id,
        signature_audit: fv.signature_audit ?? null,
      });
    }

    return templates.map((template) => {
      const userRoleIds = templateRoleMap.get(template.id) ?? [];

      // Combine editable field IDs from all roles assigned to this user
      const editableFieldIds = new Set<string>();
      for (const roleId of userRoleIds) {
        const ids = this.getFieldIdsByRole(template.document_fields, roleId);
        ids.forEach((id) => editableFieldIds.add(id));
      }

      const fields = template.document_fields.map((field: Record<string, any>) => {
        const isEditable = editableFieldIds.has(field.id);
        const saved = valueMap.get(`${template.id}:${field.id}`);
        return {
          ...field,
          isEditable,
          ...(saved
            ? {
                filledValue: saved.value,
                filledBy: saved.user_id,
                /** SignedDocumentInfo audit JSON for this field's
                 *  filledValue. Null for non-signature fields and for
                 *  legacy rows written before the column existed. */
                signatureAudit: saved.signature_audit,
              }
            : {}),
        };
      });

      return {
        template_id: template.id,
        name: template.name,
        description: template.description,
        assignedRoles: userRoleIds,
        // Ship the full role list so the filler UI can compute
        // sequential-signing state client-side (whose turn is it, who's
        // already signed) without a second round-trip. Each role carries
        // `{ id, name, color, order }`.
        roles: template.roles ?? [],
        pdfUrl: template.pdf_file_key
          ? `/v1/api/organizations/${template.organization_id}/document-workflow/templates/${template.id}/pdf/view`
          : null,
        fields,
      };
    });
  }

  /**
   * POST /v1/api/documents/:templateId/submit
   *
   * Submit field values for a user.
   * Validates user is assigned to this template with the given role.
   * Only fields with assignedRoleId matching the given roleId are accepted.
   */
  async submitFields(templateId: string, dto: SubmitExternalFieldsDto) {
    await this.validateUser(dto.userId);

    // Verify user is assigned to this template with this role
    const assignment = await this.userAssignmentRepo.findOne({
      where: {
        template_id: templateId,
        user_id: dto.userId,
        role_id: dto.roleId,
      },
    });
    if (!assignment) {
      throw new ForbiddenException('You are not assigned to this template with this role');
    }

    const template = await this.templateRepo.findOne({ where: { id: templateId } });
    if (!template) {
      throw new NotFoundException('Template not found');
    }

    const assignedFieldIds = this.getFieldIdsByRole(
      template.document_fields,
      dto.roleId,
    );

    if (assignedFieldIds.size === 0) {
      throw new ForbiddenException('No fields are assigned to this role on this template');
    }

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

    // Pre-compute which of the submitted fields are signature/initials so
    // we only do the (relatively expensive) signer-snapshot lookup once
    // per request — not once per field — and only when at least one
    // signature is being saved.
    const isSignatureField = (fieldId: string): boolean => {
      const f = (template.document_fields as Record<string, unknown>[]).find(
        (x) => (x as { id?: string }).id === fieldId,
      ) as Record<string, unknown> | undefined;
      if (!f) return false;
      const t = String(f.type ?? '').toLowerCase();
      if (t === 'signature' || t === 'initials') return true;
      const label = String(f.label ?? '').toLowerCase();
      return label.startsWith('signature') || label.startsWith('initials');
    };
    const touchesSignatureField = dto.fields.some((f) =>
      isSignatureField(f.fieldId),
    );
    const signerSnapshot = touchesSignatureField
      ? await this.resolveSignerSnapshot(
          dto.userId,
          template.organization_id ?? null,
        )
      : { name: null, title: null };
    const geolocationSnapshot = dto.geolocation
      ? {
          latitude: dto.geolocation.latitude,
          longitude: dto.geolocation.longitude,
          accuracy: dto.geolocation.accuracy ?? null,
          capturedAt: dto.geolocation.capturedAt ?? null,
        }
      : null;
    const buildSignatureAudit = (fieldId: string) => {
      if (!isSignatureField(fieldId)) return null;
      return {
        signedAt: new Date().toISOString(),
        signerName: signerSnapshot.name,
        signerTitle: signerSnapshot.title,
        geolocation: geolocationSnapshot,
      };
    };

    const saved: DocumentFieldValue[] = [];
    for (const item of dto.fields) {
      const existing = await this.fieldValueRepo.findOne({
        where: {
          template_id: templateId,
          field_id: item.fieldId,
          user_id: dto.userId,
        },
      });
      const audit = buildSignatureAudit(item.fieldId);

      if (existing) {
        existing.value = item.value;
        if (audit) existing.signature_audit = audit;
        saved.push(await this.fieldValueRepo.save(existing));
      } else {
        saved.push(
          await this.fieldValueRepo.save(
            this.fieldValueRepo.create({
              template_id: templateId,
              field_id: item.fieldId,
              user_id: dto.userId,
              value: item.value,
              signature_audit: audit,
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
      signature_audit: fv.signature_audit,
      created_at: fv.created_at,
      updated_at: fv.updated_at,
    }));
  }
}
