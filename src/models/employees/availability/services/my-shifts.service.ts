import {
  Injectable,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Employee } from '../../entities/employee.entity';
import { EmployeeShift } from '../../../organizations/scheduling/entities/employee-shift.entity';
import { QueryMyShiftsDto } from '../dto/query-my-shifts.dto';

export interface MyShiftRow {
  id: string;
  shift_id: string;
  employee_id: string;
  organization_id: string;
  organization_name: string | null;
  scheduled_date: string;
  status: string;
  notes: string | null;
  role: string | null;
  department_id: string | null;
  station_id: string | null;
  shift: {
    id: string;
    name: string | null;
    shift_type: string | null;
    start_at: string;
    end_at: string;
  };
}

function formatDateOnly(d: string | Date): string {
  if (typeof d === 'string') return d.slice(0, 10);
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

@Injectable()
export class MyShiftsService {
  constructor(
    @InjectRepository(Employee)
    private readonly employeeRepository: Repository<Employee>,
    @InjectRepository(EmployeeShift)
    private readonly employeeShiftRepository: Repository<EmployeeShift>,
  ) {}

  private async getMyEmployeeIds(userId: string): Promise<string[]> {
    const rows = await this.employeeRepository.find({
      where: { user_id: userId },
      select: ['id'],
    });
    return rows.map((r) => r.id);
  }

  async findMine(
    userId: string,
    query: QueryMyShiftsDto,
  ): Promise<{ data: MyShiftRow[]; total: number; page: number; limit: number }> {
    const { page = 1, limit = 100, from_date, to_date, organization_id, status } = query;
    const employeeIds = await this.getMyEmployeeIds(userId);
    if (employeeIds.length === 0) {
      return { data: [], total: 0, page, limit };
    }

    const qb = this.employeeShiftRepository
      .createQueryBuilder('es')
      .innerJoinAndSelect('es.shift', 'shift')
      .leftJoinAndSelect('shift.organization', 'organization')
      .where('es.employee_id IN (:...employeeIds)', { employeeIds });

    if (organization_id) qb.andWhere('shift.organization_id = :organization_id', { organization_id });
    if (from_date) qb.andWhere('es.scheduled_date >= :from_date', { from_date });
    if (to_date) qb.andWhere('es.scheduled_date <= :to_date', { to_date });
    if (status) qb.andWhere('es.status = :status', { status });

    qb.orderBy('es.scheduled_date', 'ASC')
      .addOrderBy('shift.start_at', 'ASC')
      .skip((page - 1) * limit)
      .take(limit);

    const [rows, total] = await qb.getManyAndCount();

    const data: MyShiftRow[] = rows.map((es) => ({
      id: es.id,
      shift_id: es.shift_id,
      employee_id: es.employee_id,
      organization_id: es.shift?.organization_id ?? '',
      organization_name: es.shift?.organization?.organization_name ?? null,
      scheduled_date: formatDateOnly(es.scheduled_date),
      status: es.status,
      notes: es.notes,
      role: es.role,
      department_id: es.department_id,
      station_id: es.station_id,
      shift: {
        id: es.shift?.id ?? es.shift_id,
        name: es.shift?.name ?? null,
        shift_type: es.shift?.shift_type ?? null,
        start_at: es.shift?.start_at instanceof Date
          ? es.shift.start_at.toISOString()
          : String(es.shift?.start_at ?? ''),
        end_at: es.shift?.end_at instanceof Date
          ? es.shift.end_at.toISOString()
          : String(es.shift?.end_at ?? ''),
      },
    }));

    return { data, total, page, limit };
  }

  async respond(
    userId: string,
    employeeShiftId: string,
    accept: boolean,
  ): Promise<MyShiftRow> {
    const row = await this.employeeShiftRepository.findOne({
      where: { id: employeeShiftId },
      relations: ['shift', 'shift.organization', 'employee'],
    });
    if (!row) throw new NotFoundException('Shift assignment not found');
    if (!row.employee || row.employee.user_id !== userId) {
      throw new ForbiddenException('You can only respond to your own shifts.');
    }

    row.status = accept ? 'CONFIRMED' : 'DECLINED';
    const saved = await this.employeeShiftRepository.save(row);

    return {
      id: saved.id,
      shift_id: saved.shift_id,
      employee_id: saved.employee_id,
      organization_id: row.shift?.organization_id ?? '',
      organization_name: row.shift?.organization?.organization_name ?? null,
      scheduled_date: formatDateOnly(saved.scheduled_date),
      status: saved.status,
      notes: saved.notes,
      role: saved.role,
      department_id: saved.department_id,
      station_id: saved.station_id,
      shift: {
        id: row.shift?.id ?? saved.shift_id,
        name: row.shift?.name ?? null,
        shift_type: row.shift?.shift_type ?? null,
        start_at: row.shift?.start_at instanceof Date
          ? row.shift.start_at.toISOString()
          : String(row.shift?.start_at ?? ''),
        end_at: row.shift?.end_at instanceof Date
          ? row.shift.end_at.toISOString()
          : String(row.shift?.end_at ?? ''),
      },
    };
  }
}
