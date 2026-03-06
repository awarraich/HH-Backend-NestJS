import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Employee } from '../../entities/employee.entity';
import { EmployeeContextSerializer } from '../serializers/employee-context.serializer';
import type { OrganizationContextItem } from '../serializers/employee-context.serializer';

@Injectable()
export class EmployeeContextService {
  private readonly serializer = new EmployeeContextSerializer();

  constructor(
    @InjectRepository(Employee)
    private readonly employeeRepository: Repository<Employee>,
  ) {}

  /**
   * Returns employee info and all organizations the employee belongs to,
   * with per-org status and is_active_context (from client's currentOrganizationId).
   * Resolves the employee from the JWT userId (no employeeId in path).
   */
  async getContextByUserId(
    userId: string,
    currentOrganizationId?: string | null,
  ): Promise<ReturnType<EmployeeContextSerializer['serializeContext']>> {
    const employee = await this.employeeRepository.findOne({
      where: { user_id: userId },
      relations: ['user', 'profile'],
      order: { created_at: 'ASC' },
    });

    if (!employee) {
      throw new NotFoundException(
        'No employee record found for this user. You may not be linked to any organization.',
      );
    }

    const memberships = await this.employeeRepository.find({
      where: { user_id: userId },
      relations: ['organization', 'providerRole'],
      order: { created_at: 'ASC' },
    });

    const organizations: OrganizationContextItem[] = memberships.map((row) => ({
      organization_id: row.organization_id!,
      organization_name: row.organization?.organization_name ?? null,
      employee_status: row.status,
      is_active_context:
        currentOrganizationId != null && row.organization_id === currentOrganizationId,
      provider_role: row.providerRole
        ? {
            id: row.providerRole.id,
            code: row.providerRole.code,
            name: row.providerRole.name,
          }
        : null,
    }));

    return this.serializer.serializeContext(employee, organizations);
  }
}
