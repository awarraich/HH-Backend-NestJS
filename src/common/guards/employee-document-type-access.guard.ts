import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Inject,
  forwardRef,
} from '@nestjs/common';
import { UserWithRolesInterface } from '../interfaces/user-with-roles.interface';
import { OrganizationRoleService } from '../../models/organizations/services/organization-role.service';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Employee } from '../../models/employees/entities/employee.entity';

@Injectable()
export class EmployeeDocumentTypeAccessGuard implements CanActivate {
  constructor(
    @Inject(forwardRef(() => OrganizationRoleService))
    private readonly organizationRoleService: OrganizationRoleService,
    @InjectRepository(Employee)
    private readonly employeeRepository: Repository<Employee>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const user: UserWithRolesInterface = request.user;
    const employeeId = request.params?.employeeId;

    if (!user?.userId) {
      throw new ForbiddenException('User not found');
    }
    if (!employeeId) {
      throw new ForbiddenException('Employee ID is required');
    }

    const employee = await this.employeeRepository.findOne({
      where: { id: employeeId },
    });
    if (!employee) {
      throw new ForbiddenException('Employee not found');
    }
    if (employee.user_id === user.userId) return true;
    if (employee.organization_id) {
      const hasRole = await this.organizationRoleService.hasAnyRoleInOrganization(
        user.userId,
        employee.organization_id,
        ['OWNER', 'HR', 'MANAGER'],
      );
      if (hasRole) return true;
    }
    throw new ForbiddenException(
      'You do not have permission to access this employee\'s document types.',
    );
  }
}
