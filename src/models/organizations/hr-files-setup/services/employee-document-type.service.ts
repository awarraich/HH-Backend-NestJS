import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  ConflictException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, IsNull } from 'typeorm';
import { HrDocumentType } from '../entities/hr-document-type.entity';
import { EmployeeDocument } from '../entities/employee-document.entity';
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
    await this.ensureAccess(employeeId, userId);
    const customTypes = await this.hrDocumentTypeRepository.find({
      where: {
        employee_id: employeeId,
        organization_id: IsNull(),
        is_active: true,
      },
      order: { sort_order: 'ASC', id: 'ASC' },
    });
    const documents = await this.employeeDocumentRepository.find({
      where: { employee_id: employeeId, deleted_at: IsNull() },
    });
    const docByTypeId = new Map(documents.map((d) => [d.document_type_id, d]));
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
    const toItem = (dt: HrDocumentType): EmployeeDocumentTypeWithDocumentItem => {
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
          is_custom: true,
        },
        document: doc ? toDoc(doc) : null,
      };
    };
    return customTypes.map(toItem);
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
