import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { Department } from '../entities/department.entity';
import { DepartmentStaff } from '../entities/department-staff.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CreateDepartmentStaffDto } from '../dto/create-department-staff.dto';
import { UpdateDepartmentStaffDto } from '../dto/update-department-staff.dto';

@Injectable()
export class DepartmentStaffService {
  constructor(
    @InjectRepository(DepartmentStaff)
    private readonly staffRepository: Repository<DepartmentStaff>,
    @InjectRepository(Department)
    private readonly departmentRepository: Repository<Department>,
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
    if (!canAccess) throw new ForbiddenException('No access to this organization.');
    const org = await this.organizationRepository.findOne({ where: { id: organizationId } });
    if (!org) throw new NotFoundException('Organization not found');
  }

  private async ensureDepartment(organizationId: string, departmentId: string): Promise<Department> {
    const dept = await this.departmentRepository.findOne({
      where: { id: departmentId, organization_id: organizationId },
    });
    if (!dept) throw new NotFoundException('Department not found');
    return dept;
  }

  async findAll(
    organizationId: string,
    departmentId: string,
    userId: string,
  ): Promise<DepartmentStaff[]> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureDepartment(organizationId, departmentId);
    return this.staffRepository.find({
      where: { department_id: departmentId },
      order: { sort_order: 'ASC', staff_name: 'ASC' },
    });
  }

  async findOne(
    organizationId: string,
    departmentId: string,
    staffId: string,
    userId: string,
  ): Promise<DepartmentStaff> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureDepartment(organizationId, departmentId);
    const staff = await this.staffRepository.findOne({
      where: { id: staffId, department_id: departmentId },
    });
    if (!staff) throw new NotFoundException('Department staff record not found');
    return staff;
  }

  async create(
    organizationId: string,
    departmentId: string,
    dto: CreateDepartmentStaffDto,
    userId: string,
  ): Promise<DepartmentStaff> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureDepartment(organizationId, departmentId);
    const staff = this.staffRepository.create({
      department_id: departmentId,
      provider_role_id: dto.provider_role_id ?? null,
      staff_type: dto.staff_type,
      staff_name: dto.staff_name,
      quantity: dto.quantity ?? 1,
      assignment_level: dto.assignment_level ?? null,
      assignment_type: dto.assignment_type ?? null,
      shift_ids: dto.shift_ids ?? null,
      staff_by_shift: dto.staff_by_shift ?? null,
      staff_min_max_by_shift: dto.staff_min_max_by_shift ?? null,
      sort_order: dto.sort_order ?? null,
    });
    return this.staffRepository.save(staff);
  }

  async update(
    organizationId: string,
    departmentId: string,
    staffId: string,
    dto: UpdateDepartmentStaffDto,
    userId: string,
  ): Promise<DepartmentStaff> {
    await this.ensureAccess(organizationId, userId);
    const staff = await this.findOne(organizationId, departmentId, staffId, userId);
    if (dto.provider_role_id !== undefined) staff.provider_role_id = dto.provider_role_id ?? null;
    if (dto.staff_type !== undefined) staff.staff_type = dto.staff_type;
    if (dto.staff_name !== undefined) staff.staff_name = dto.staff_name;
    if (dto.quantity !== undefined) staff.quantity = dto.quantity;
    if (dto.assignment_level !== undefined) staff.assignment_level = dto.assignment_level;
    if (dto.assignment_type !== undefined) staff.assignment_type = dto.assignment_type;
    if (dto.shift_ids !== undefined) staff.shift_ids = dto.shift_ids;
    if (dto.staff_by_shift !== undefined) staff.staff_by_shift = dto.staff_by_shift;
    if (dto.staff_min_max_by_shift !== undefined) staff.staff_min_max_by_shift = dto.staff_min_max_by_shift;
    if (dto.sort_order !== undefined) staff.sort_order = dto.sort_order;
    return this.staffRepository.save(staff);
  }

  async remove(
    organizationId: string,
    departmentId: string,
    staffId: string,
    userId: string,
  ): Promise<void> {
    await this.ensureAccess(organizationId, userId);
    const staff = await this.findOne(organizationId, departmentId, staffId, userId);
    await this.staffRepository.remove(staff);
  }
}
