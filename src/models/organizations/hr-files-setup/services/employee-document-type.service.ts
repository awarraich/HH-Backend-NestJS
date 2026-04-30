import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  ConflictException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, IsNull, Repository } from 'typeorm';
import { HrDocumentType } from '../entities/hr-document-type.entity';
import { EmployeeDocument } from '../entities/employee-document.entity';
import { EmployeeRequirementTag } from '../entities/employee-requirement-tag.entity';
import { RequirementDocumentType } from '../entities/requirement-document-type.entity';
import { Employee } from '../../../employees/entities/employee.entity';
import { Organization } from '../../entities/organization.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CreateHrDocumentTypeDto } from '../dto/create-hr-document-type.dto';
import { UpdateHrDocumentTypeDto } from '../dto/update-hr-document-type.dto';

export interface EmployeeDocumentTypeWithDocumentItem {
  document_type: {
    id: string;
    code: string;
    name: string;
    has_expiration: boolean;
    is_required: boolean;
    category: string | null;
    sort_order: number;
    is_custom: boolean;
  };
  /**
   * `true` when the type is part of the employee's CURRENT profile —
   * a custom type they made or a type their active requirement tags pull
   * in. `false` when the type is only here because they uploaded a file
   * for it under a previous template (carry-over). The UI surfaces these
   * separately so the employee can still see / re-download the file.
   */
  is_currently_required: boolean;
  document: {
    id: string;
    file_name: string;
    file_path: string;
    file_size_bytes: number | null;
    mime_type: string | null;
    extraction_status: string;
    created_at: Date;
  } | null;
}

@Injectable()
export class EmployeeDocumentTypeService {
  constructor(
    @InjectRepository(HrDocumentType)
    private readonly hrDocumentTypeRepository: Repository<HrDocumentType>,
    @InjectRepository(EmployeeDocument)
    private readonly employeeDocumentRepository: Repository<EmployeeDocument>,
    @InjectRepository(Employee)
    private readonly employeeRepository: Repository<Employee>,
    @InjectRepository(Organization)
    private readonly organizationRepository: Repository<Organization>,
    @InjectRepository(EmployeeRequirementTag)
    private readonly employeeRequirementTagRepository: Repository<EmployeeRequirementTag>,
    @InjectRepository(RequirementDocumentType)
    private readonly requirementDocumentTypeRepository: Repository<RequirementDocumentType>,
    private readonly organizationRoleService: OrganizationRoleService,
  ) {}

  private async ensureAccess(employeeId: string, userId: string): Promise<Employee> {
    const employee = await this.employeeRepository.findOne({
      where: { id: employeeId },
    });
    if (!employee) {
      throw new NotFoundException('Employee not found');
    }
    if (employee.user_id === userId) return employee;
    if (employee.organization_id) {
      const hasRole = await this.organizationRoleService.hasAnyRoleInOrganization(
        userId,
        employee.organization_id,
        ['OWNER', 'HR', 'MANAGER'],
      );
      if (hasRole) return employee;
    }
    throw new ForbiddenException(
      "You do not have permission to access this employee's document types.",
    );
  }

  async listForEmployee(
    employeeId: string,
    userId: string,
  ): Promise<EmployeeDocumentTypeWithDocumentItem[]> {
    const employee = await this.ensureAccess(employeeId, userId);

    // Custom types — created by the employee themselves (organization_id is
    // NULL on these). These are always shown so the employee can manage
    // their own self-defined doc types even before uploading a file.
    const customTypes = await this.hrDocumentTypeRepository.find({
      where: {
        employee_id: employeeId,
        organization_id: IsNull(),
        is_active: true,
      },
      order: { sort_order: 'ASC', id: 'ASC' },
    });

    // Documents the employee has uploaded or had auto-archived (e.g. signed
    // offer letter). Some of these will be against custom types (handled
    // above), others against org-scoped types (e.g. OFFER_LETTER) that
    // wouldn't otherwise appear in the employee's My Documents.
    const documents = await this.employeeDocumentRepository.find({
      where: { employee_id: employeeId, deleted_at: IsNull() },
    });
    const docByTypeId = new Map(documents.map((d) => [d.document_type_id, d]));

    // Resolve any non-custom doc types the employee has files for —
    // org-scoped types (their org's catalog) so we can render them.
    const customTypeIds = new Set(customTypes.map((t) => t.id));
    const extraTypeIds = [...docByTypeId.keys()].filter(
      (id) => !customTypeIds.has(id),
    );
    const extraTypes = extraTypeIds.length
      ? await this.hrDocumentTypeRepository.find({
          where: {
            id: In(extraTypeIds),
            organization_id: employee.organization_id ?? IsNull(),
            is_active: true,
          },
        })
      : [];

    // Compute which doc-type ids the CURRENT requirement tags pull in. An
    // extra (non-custom) type that's NOT in this set is a carry-over from
    // a previous template — the file is preserved + visible, but the UI
    // can label it accordingly so the employee/HR understands its status.
    const currentlyRequiredExtraTypeIds = await this.computeCurrentlyRequiredTypeIds(
      employeeId,
      extraTypeIds,
    );

    const toDoc = (
      d: EmployeeDocument,
    ): Pick<
      EmployeeDocument,
      | 'id'
      | 'file_name'
      | 'file_path'
      | 'file_size_bytes'
      | 'mime_type'
      | 'extraction_status'
      | 'created_at'
    > => ({
      id: d.id,
      file_name: d.file_name,
      file_path: d.file_path,
      file_size_bytes: d.file_size_bytes,
      mime_type: d.mime_type,
      extraction_status: d.extraction_status,
      created_at: d.created_at,
    });

    const toItem = (
      dt: HrDocumentType,
      isCustom: boolean,
      isCurrentlyRequired: boolean,
    ): EmployeeDocumentTypeWithDocumentItem => {
      const doc = docByTypeId.get(dt.id);
      return {
        document_type: {
          id: dt.id,
          code: dt.code,
          name: dt.name,
          has_expiration: dt.has_expiration,
          is_required: dt.is_required,
          category: dt.category,
          sort_order: dt.sort_order,
          is_custom: isCustom,
        },
        is_currently_required: isCurrentlyRequired,
        document: doc ? toDoc(doc) : null,
      };
    };

    return [
      // Custom types are always part of the employee's current profile
      // (the employee themselves added them).
      ...customTypes.map((dt) => toItem(dt, true, true)),
      // Extra (org-scoped) types are "currently required" only if the
      // employee's active tags pull them in; otherwise they're carry-over
      // files from a previous template.
      ...extraTypes.map((dt) =>
        toItem(dt, false, currentlyRequiredExtraTypeIds.has(dt.id)),
      ),
    ];
  }

  /**
   * Of the candidate doc-type ids passed in, return the subset that the
   * employee's CURRENT requirement tags actively pull in. Used to
   * distinguish carry-over docs (uploaded under a previous template) from
   * docs the active template still requires.
   *
   * Pre-filtered scope keeps this query small — we never join across the
   * whole org's requirement_document_types table.
   */
  private async computeCurrentlyRequiredTypeIds(
    employeeId: string,
    candidateTypeIds: string[],
  ): Promise<Set<string>> {
    if (candidateTypeIds.length === 0) return new Set();
    const tagLinks = await this.employeeRequirementTagRepository.find({
      where: { employee_id: employeeId },
      select: ['requirement_tag_id'],
    });
    if (tagLinks.length === 0) return new Set();
    const reqLinks = await this.requirementDocumentTypeRepository.find({
      where: {
        requirement_tag_id: In(tagLinks.map((l) => l.requirement_tag_id)),
        document_type_id: In(candidateTypeIds),
      },
      select: ['document_type_id'],
    });
    return new Set(reqLinks.map((l) => l.document_type_id));
  }

  async createForEmployee(
    employeeId: string,
    dto: CreateHrDocumentTypeDto,
    userId: string,
  ): Promise<HrDocumentType> {
    await this.ensureAccess(employeeId, userId);
    const existing = await this.hrDocumentTypeRepository.findOne({
      where: {
        employee_id: employeeId,
        organization_id: IsNull(),
        code: dto.code,
      },
    });
    if (existing) {
      throw new ConflictException(
        `A document type with code "${dto.code}" already exists for this employee.`,
      );
    }
    const entity = this.hrDocumentTypeRepository.create({
      organization_id: null,
      employee_id: employeeId,
      code: dto.code,
      name: dto.name,
      has_expiration: dto.has_expiration ?? false,
      is_required: false,
      category: dto.category ?? null,
      sort_order: dto.sort_order ?? 0,
      is_active: true,
    });
    return this.hrDocumentTypeRepository.save(entity);
  }

  async updateForEmployee(
    employeeId: string,
    typeId: string,
    dto: UpdateHrDocumentTypeDto,
    userId: string,
  ): Promise<HrDocumentType> {
    await this.ensureAccess(employeeId, userId);
    const entity = await this.hrDocumentTypeRepository.findOne({
      where: { id: typeId, employee_id: employeeId, organization_id: IsNull() },
    });
    if (!entity) {
      throw new NotFoundException('Document type not found');
    }
    if (dto.name !== undefined) entity.name = dto.name;
    if (dto.has_expiration !== undefined) entity.has_expiration = dto.has_expiration;
    if (dto.is_required !== undefined) entity.is_required = dto.is_required;
    if (dto.category !== undefined) entity.category = dto.category;
    if (dto.sort_order !== undefined) entity.sort_order = dto.sort_order;
    if (dto.is_active !== undefined) entity.is_active = dto.is_active;
    return this.hrDocumentTypeRepository.save(entity);
  }

  async removeForEmployee(employeeId: string, typeId: string, userId: string): Promise<void> {
    await this.ensureAccess(employeeId, userId);
    const entity = await this.hrDocumentTypeRepository.findOne({
      where: { id: typeId, employee_id: employeeId, organization_id: IsNull() },
    });
    if (!entity) {
      throw new NotFoundException('Document type not found');
    }
    entity.is_active = false;
    await this.hrDocumentTypeRepository.save(entity);
  }
}
