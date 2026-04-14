import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { DepartmentConfigOption } from '../entities/department-config-option.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CreateDepartmentConfigOptionDto } from '../dto/create-department-config-option.dto';
import { UpdateDepartmentConfigOptionDto } from '../dto/update-department-config-option.dto';
import { QueryDepartmentConfigOptionDto } from '../dto/query-department-config-option.dto';

/** System defaults seeded when an organization has no config options yet. */
const DEFAULT_OPTIONS: Array<{
  category: string;
  value: string;
  label: string;
  description?: string;
  icon?: string;
  sort_order: number;
}> = [
  // Department types
  { category: 'DEPARTMENT_TYPE', value: 'NURSING', label: 'Nursing Department', description: 'Traditional nursing stations with rooms and beds', icon: '🏥', sort_order: 1 },
  { category: 'DEPARTMENT_TYPE', value: 'CLINIC', label: 'Dr. Clinic', description: 'Medical clinic with rooms and chairs', icon: '🩺', sort_order: 2 },
  { category: 'DEPARTMENT_TYPE', value: 'NURSING_HOME', label: 'Nursing Home', description: 'Long-term care facility with nursing stations', icon: '🏠', sort_order: 3 },
  { category: 'DEPARTMENT_TYPE', value: 'OTHER', label: 'Other', description: 'Custom department type', icon: '🏢', sort_order: 4 },

  // Layout types
  { category: 'LAYOUT_TYPE', value: 'stations', label: 'Stations & Rooms', description: 'Nursing stations with rooms and beds', icon: '🏥', sort_order: 1 },
  { category: 'LAYOUT_TYPE', value: 'rooms', label: 'Rooms & Beds', description: 'Patient rooms with beds and chairs', icon: '🛏️', sort_order: 2 },
  { category: 'LAYOUT_TYPE', value: 'staff-only', label: 'Staff Only', description: 'Just staff, no physical layout', icon: '👥', sort_order: 3 },
  { category: 'LAYOUT_TYPE', value: 'field', label: 'Field / Visits', description: 'Home visits and field assignments', icon: '📍', sort_order: 4 },
  { category: 'LAYOUT_TYPE', value: 'fleet', label: 'Fleet / Routes', description: 'Vehicles and transportation routes', icon: '🚐', sort_order: 5 },
  { category: 'LAYOUT_TYPE', value: 'lab', label: 'Lab / Workstations', description: 'Lab workstations and instruments', icon: '🔬', sort_order: 6 },

  // Room types
  { category: 'ROOM_TYPE', value: 'standard', label: 'Standard Patient Room', icon: '🛏️', sort_order: 1 },
  { category: 'ROOM_TYPE', value: 'icu', label: 'ICU Room', icon: '🫀', sort_order: 2 },
  { category: 'ROOM_TYPE', value: 'operation', label: 'Operation Room', icon: '🔬', sort_order: 3 },
  { category: 'ROOM_TYPE', value: 'surgery', label: 'Surgery Room', icon: '⚕️', sort_order: 4 },
  { category: 'ROOM_TYPE', value: 'therapy', label: 'Therapy Room', icon: '💪', sort_order: 5 },
  { category: 'ROOM_TYPE', value: 'recovery', label: 'Recovery Room', icon: '🩹', sort_order: 6 },
  { category: 'ROOM_TYPE', value: 'emergency', label: 'Emergency Room', icon: '🚨', sort_order: 7 },
  { category: 'ROOM_TYPE', value: 'isolation', label: 'Isolation Room', icon: '🔒', sort_order: 8 },
  { category: 'ROOM_TYPE', value: 'consultation', label: 'Consultation Room', icon: '💬', sort_order: 9 },
  { category: 'ROOM_TYPE', value: 'other', label: 'Other', icon: '📋', sort_order: 10 },

  // Configuration types (beds vs chairs)
  { category: 'CONFIGURATION_TYPE', value: 'BEDS', label: 'Patient Beds', icon: '🛏️', sort_order: 1 },
  { category: 'CONFIGURATION_TYPE', value: 'CHAIRS', label: 'Treatment Chairs', icon: '🪑', sort_order: 2 },

  // Vehicle types (fleet layout)
  { category: 'VEHICLE_TYPE', value: 'wheelchair_van', label: 'Wheelchair Van', icon: '🚐', sort_order: 1 },
  { category: 'VEHICLE_TYPE', value: 'sedan', label: 'Sedan', icon: '🚗', sort_order: 2 },
  { category: 'VEHICLE_TYPE', value: 'ambulance', label: 'Ambulance', icon: '🚑', sort_order: 3 },
  { category: 'VEHICLE_TYPE', value: 'mini_bus', label: 'Mini-Bus', icon: '🚌', sort_order: 4 },
  { category: 'VEHICLE_TYPE', value: 'suv', label: 'SUV', icon: '🚙', sort_order: 5 },

  // Workstation types (lab layout)
  { category: 'WORKSTATION_TYPE', value: 'dispensing', label: 'Dispensing', icon: '💊', sort_order: 1 },
  { category: 'WORKSTATION_TYPE', value: 'compounding', label: 'Compounding', icon: '🧪', sort_order: 2 },
  { category: 'WORKSTATION_TYPE', value: 'verification', label: 'Verification', icon: '✅', sort_order: 3 },
  { category: 'WORKSTATION_TYPE', value: 'lab_testing', label: 'Lab Testing', icon: '🔬', sort_order: 4 },
  { category: 'WORKSTATION_TYPE', value: 'microscope', label: 'Microscope', icon: '🔍', sort_order: 5 },
  { category: 'WORKSTATION_TYPE', value: 'quality_control', label: 'Quality Control', icon: '📋', sort_order: 6 },
];

@Injectable()
export class DepartmentConfigOptionService {
  constructor(
    @InjectRepository(DepartmentConfigOption)
    private readonly repo: Repository<DepartmentConfigOption>,
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

  /**
   * Find all config options for an organization, filtered by optional category.
   * Seeds defaults on first access if none exist.
   */
  async findAll(
    organizationId: string,
    query: QueryDepartmentConfigOptionDto,
    userId: string,
  ): Promise<DepartmentConfigOption[]> {
    await this.ensureAccess(organizationId, userId);

    // Check if any options exist; seed if not
    const count = await this.repo.count({ where: { organization_id: organizationId } });
    if (count === 0) {
      await this.seedDefaults(organizationId);
    }

    const qb = this.repo
      .createQueryBuilder('o')
      .where('o.organization_id = :organizationId', { organizationId });

    if (query.category) {
      qb.andWhere('o.category = :category', { category: query.category });
    }
    if (query.is_active !== undefined) {
      qb.andWhere('o.is_active = :is_active', { is_active: query.is_active });
    }

    qb.orderBy('o.category', 'ASC')
      .addOrderBy('o.sort_order', 'ASC', 'NULLS LAST')
      .addOrderBy('o.label', 'ASC');

    return qb.getMany();
  }

  async findOne(
    organizationId: string,
    optionId: string,
    userId: string,
  ): Promise<DepartmentConfigOption> {
    await this.ensureAccess(organizationId, userId);
    const option = await this.repo.findOne({
      where: { id: optionId, organization_id: organizationId },
    });
    if (!option) throw new NotFoundException('Config option not found');
    return option;
  }

  async create(
    organizationId: string,
    dto: CreateDepartmentConfigOptionDto,
    userId: string,
  ): Promise<DepartmentConfigOption> {
    await this.ensureAccess(organizationId, userId);
    const option = this.repo.create({
      organization_id: organizationId,
      category: dto.category,
      value: dto.value,
      label: dto.label,
      description: dto.description ?? null,
      icon: dto.icon ?? null,
      is_default: false,
      is_active: dto.is_active ?? true,
      sort_order: dto.sort_order ?? null,
    });
    return this.repo.save(option);
  }

  async update(
    organizationId: string,
    optionId: string,
    dto: UpdateDepartmentConfigOptionDto,
    userId: string,
  ): Promise<DepartmentConfigOption> {
    await this.ensureAccess(organizationId, userId);
    const option = await this.findOne(organizationId, optionId, userId);
    if (dto.value !== undefined) option.value = dto.value;
    if (dto.label !== undefined) option.label = dto.label;
    if (dto.description !== undefined) option.description = dto.description ?? null;
    if (dto.icon !== undefined) option.icon = dto.icon ?? null;
    if (dto.is_active !== undefined) option.is_active = dto.is_active;
    if (dto.sort_order !== undefined) option.sort_order = dto.sort_order ?? null;
    return this.repo.save(option);
  }

  async remove(
    organizationId: string,
    optionId: string,
    userId: string,
  ): Promise<void> {
    await this.ensureAccess(organizationId, userId);
    const option = await this.findOne(organizationId, optionId, userId);
    await this.repo.remove(option);
  }

  /** Seed default config options for a new organization. */
  private async seedDefaults(organizationId: string): Promise<void> {
    const entities = DEFAULT_OPTIONS.map((opt) =>
      this.repo.create({
        organization_id: organizationId,
        category: opt.category,
        value: opt.value,
        label: opt.label,
        description: opt.description ?? null,
        icon: opt.icon ?? null,
        is_default: true,
        is_active: true,
        sort_order: opt.sort_order,
      }),
    );
    await this.repo.save(entities);
  }
}
