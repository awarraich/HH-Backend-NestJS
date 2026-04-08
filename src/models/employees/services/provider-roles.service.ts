import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { ProviderRole } from '../entities/provider-role.entity';
import { Employee } from '../entities/employee.entity';
import { EmployeeShift } from '../../organizations/scheduling/entities/employee-shift.entity';

export interface ProviderRoleWithEmployeeCount extends ProviderRole {
  employee_count: number;
}

@Injectable()
export class ProviderRolesService {
  constructor(
    @InjectRepository(ProviderRole)
    private readonly providerRoleRepository: Repository<ProviderRole>,
    @InjectRepository(Employee)
    private readonly employeeRepository: Repository<Employee>,
    @InjectRepository(EmployeeShift)
    private readonly employeeShiftRepository: Repository<EmployeeShift>,
  ) {}

  /**
   * Returns all provider roles (e.g. Sitter, RC, LN) for reference/dropdowns.
   */
  async findAll(): Promise<ProviderRole[]> {
    return this.providerRoleRepository.find({ order: { code: 'ASC' } });
  }

  /**
   * Returns all provider roles, optionally scoped to those held by employees
   * within a specific organization.
   */
  async listForOrganization(organizationId?: string): Promise<ProviderRole[]> {
    if (!organizationId) return this.findAll();

    const employees = await this.employeeRepository.find({
      where: { organization_id: organizationId },
      select: ['provider_role_id'],
    });
    const roleIds = Array.from(
      new Set(
        employees
          .map((e) => e.provider_role_id)
          .filter((id): id is string => id !== null),
      ),
    );
    if (roleIds.length === 0) return [];
    return this.providerRoleRepository.find({
      where: { id: In(roleIds) },
      order: { code: 'ASC' },
    });
  }

  async findOne(roleId: string): Promise<ProviderRole> {
    const role = await this.providerRoleRepository.findOne({ where: { id: roleId } });
    if (!role) throw new NotFoundException('Provider role not found');
    return role;
  }

  
  async resolveByCodeOrName(query: string): Promise<ProviderRole[]> {
    const trimmed = query.trim();
    if (!trimmed) return [];

    // 1. Exact code (case-insensitive)
    const byCode = await this.providerRoleRepository
      .createQueryBuilder('r')
      .where('LOWER(r.code) = :q', { q: trimmed.toLowerCase() })
      .getMany();
    if (byCode.length > 0) return byCode;

    // 2. Exact name (case-insensitive)
    const byName = await this.providerRoleRepository
      .createQueryBuilder('r')
      .where('LOWER(r.name) = :q', { q: trimmed.toLowerCase() })
      .getMany();
    if (byName.length > 0) return byName;

    // 3. Fuzzy fallback
    return this.searchByText(trimmed, 10);
  }

  /**
   * Free-text search across role code, name, and description.
   */
  async searchByText(query: string, limit = 25): Promise<ProviderRole[]> {
    const trimmed = query.trim();
    if (!trimmed) return [];

    return this.providerRoleRepository
      .createQueryBuilder('r')
      .where(
        '(LOWER(r.code) LIKE :q OR LOWER(r.name) LIKE :q OR LOWER(r.description) LIKE :q)',
        { q: `%${trimmed.toLowerCase()}%` },
      )
      .orderBy('r.code', 'ASC')
      .take(limit)
      .getMany();
  }

  /**
   * Returns the provider role held by an employee, scoped to the organization.
   * In this codebase an employee has exactly one role, but the return type is
   * an array to keep the MCP tool surface stable.
   */
  async findRolesForEmployee(
    employeeId: string,
    organizationId: string,
  ): Promise<ProviderRole[]> {
    const employee = await this.employeeRepository.findOne({
      where: { id: employeeId, organization_id: organizationId },
    });
    if (!employee) throw new NotFoundException('Employee not found in organization');
    if (!employee.provider_role_id) return [];
    const role = await this.providerRoleRepository.findOne({
      where: { id: employee.provider_role_id },
    });
    return role ? [role] : [];
  }

  /**
   * Returns the distinct provider roles represented in a shift's assignments.
   * Each role is annotated with how many employees on the shift hold it.
   */
  async findRolesForShift(shiftId: string): Promise<ProviderRoleWithEmployeeCount[]> {
    const assignments = await this.employeeShiftRepository.find({
      where: { shift_id: shiftId },
      relations: ['employee'],
    });
    if (assignments.length === 0) return [];

    const counts = new Map<string, number>();
    for (const a of assignments) {
      const roleId = a.employee?.provider_role_id;
      if (!roleId) continue;
      counts.set(roleId, (counts.get(roleId) ?? 0) + 1);
    }
    if (counts.size === 0) return [];

    const roles = await this.providerRoleRepository.find({
      where: { id: In(Array.from(counts.keys())) },
      order: { code: 'ASC' },
    });
    return roles.map((role) => ({ ...role, employee_count: counts.get(role.id) ?? 0 }));
  }
}
