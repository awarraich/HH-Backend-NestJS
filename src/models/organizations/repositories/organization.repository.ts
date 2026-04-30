import { Injectable } from '@nestjs/common';
import { DataSource, Repository } from 'typeorm';
import { Organization } from '../entities/organization.entity';

@Injectable()
export class OrganizationRepository extends Repository<Organization> {
  constructor(private dataSource: DataSource) {
    super(Organization, dataSource.createEntityManager());
  }

  async findByUserId(userId: string): Promise<Organization | null> {
    return this.findOne({
      where: { user_id: userId },
      relations: ['profile', 'typeAssignments', 'typeAssignments.organizationType'],
    });
  }

  async findOrganizationsByStaffUserId(userId: string): Promise<Organization[]> {
    return this.createQueryBuilder('org')
      .innerJoin(
        'organization_staff',
        'os',
        'os.organization_id = org.id AND os.user_id = :userId AND os.status = :status',
        {
          userId,
          status: 'ACTIVE',
        },
      )
      .leftJoinAndSelect('org.profile', 'profile')
      .leftJoinAndSelect('org.typeAssignments', 'ta')
      .leftJoinAndSelect('ta.organizationType', 'ot')
      .getMany();
  }

  /**
   * Org membership via the `employees` table — covers dual-role users who
   * are primarily employees but were granted STAFF context. Their
   * `OrganizationStaff` row may not exist yet (provisioning lag) but the
   * Employee record is the authoritative org link, so the staff dashboard
   * can still resolve "which org am I in".
   */
  async findOrganizationsByEmployeeUserId(userId: string): Promise<Organization[]> {
    return this.createQueryBuilder('org')
      .innerJoin(
        'employees',
        'e',
        'e.organization_id = org.id AND e.user_id = :userId AND e.deleted_at IS NULL',
        { userId },
      )
      .leftJoinAndSelect('org.profile', 'profile')
      .leftJoinAndSelect('org.typeAssignments', 'ta')
      .leftJoinAndSelect('ta.organizationType', 'ot')
      .getMany();
  }

  async findByIdWithRelations(id: string): Promise<Organization | null> {
    return this.findOne({
      where: { id },
      relations: [
        'user',
        'profile',
        'typeAssignments',
        'typeAssignments.organizationType',
        'rolePermissions',
      ],
    });
  }
}
