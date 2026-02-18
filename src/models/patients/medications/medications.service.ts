import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In, IsNull } from 'typeorm';
import { PatientMedication } from './entities/patient-medication.entity';
import { PatientMedicationTimeSlot } from './entities/patient-medication-time-slot.entity';
import { MedicationAdministration } from './entities/medication-administration.entity';
import { CreateMedicationDto } from './dto/create-medication.dto';
import { UpdateMedicationDto } from './dto/update-medication.dto';
import { UpdateMedicationInventoryDto } from './dto/update-medication-inventory.dto';
import { MarkMedicationTakenDto } from './dto/mark-medication-taken.dto';
import { AuditLogService } from '../../../common/services/audit/audit-log.service';

export interface MedicationAuditContext {
  userId: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface TakenForDateItem {
  timeSlot: string;
  taken: boolean;
  recordedAt: string | null;
}

export interface MedicationResponse {
  id: string;
  patientId: string;
  name: string;
  dosage: string | null;
  form: string | null;
  frequency: string | null;
  prescribedBy: string | null;
  instructions: string | null;
  startDate: string | null;
  onHand: number;
  totalQuantity: number;
  unit: string | null;
  timeSlots: string[];
  takenForDate: TakenForDateItem[];
  createdAt: string;
  updatedAt: string;
}

export interface MedicationInventoryResponse {
  id: string;
  patientId: string;
  onHand: number;
  totalQuantity: number;
  unit: string | null;
  updatedAt: string;
}

@Injectable()
export class MedicationsService {
  constructor(
    @InjectRepository(PatientMedication)
    private medicationRepository: Repository<PatientMedication>,
    @InjectRepository(PatientMedicationTimeSlot)
    private timeSlotRepository: Repository<PatientMedicationTimeSlot>,
    @InjectRepository(MedicationAdministration)
    private administrationRepository: Repository<MedicationAdministration>,
    private auditLogService: AuditLogService,
  ) {}

  private toResponse(
    med: PatientMedication,
    administrations: MedicationAdministration[] = [],
  ): MedicationResponse {
    const timeSlots = (med.time_slots ?? [])
      .slice()
      .sort((a, b) => a.sort_order - b.sort_order)
      .map((s) => s.time_of_day ?? '');
    const takenForDate: TakenForDateItem[] = administrations.map((a) => ({
      timeSlot: a.time_slot ?? '',
      taken: a.taken,
      recordedAt:
        a.taken_at == null
          ? null
          : a.taken_at instanceof Date
            ? a.taken_at.toISOString()
            : String(a.taken_at),
    }));
    return {
      id: med.id,
      patientId: med.patient_id,
      name: med.name,
      dosage: med.dosage ?? null,
      form: med.form ?? null,
      frequency: med.frequency ?? null,
      prescribedBy: med.prescribed_by ?? null,
      instructions: med.instructions ?? null,
      startDate:
        med.start_date == null
          ? null
          : med.start_date instanceof Date
            ? med.start_date.toISOString().slice(0, 10)
            : String(med.start_date).slice(0, 10),
      onHand: med.on_hand,
      totalQuantity: med.total_quantity,
      unit: med.unit ?? null,
      timeSlots,
      takenForDate,
      createdAt:
        med.created_at instanceof Date
          ? med.created_at.toISOString()
          : String(med.created_at),
      updatedAt:
        med.updated_at instanceof Date
          ? med.updated_at.toISOString()
          : String(med.updated_at),
    };
  }

  private toInventoryResponse(med: PatientMedication): MedicationInventoryResponse {
    return {
      id: med.id,
      patientId: med.patient_id,
      onHand: med.on_hand,
      totalQuantity: med.total_quantity,
      unit: med.unit ?? null,
      updatedAt: med.updated_at.toISOString(),
    };
  }

  async findAll(
    patientId: string,
    date?: string,
    auditContext?: MedicationAuditContext,
  ): Promise<MedicationResponse[]> {
    const list = await this.medicationRepository.find({
      where: { patient_id: patientId, deleted_at: IsNull() },
      relations: ['time_slots'],
      order: { created_at: 'DESC' },
    });
    const queryDate =
      date ?? new Date().toISOString().slice(0, 10);
    const medIds = list.map((m) => m.id);
    let administrations: MedicationAdministration[] = [];
    if (medIds.length > 0) {
      administrations = await this.administrationRepository.find({
        where: {
          patient_medication_id: In(medIds),
          scheduled_date: new Date(queryDate),
        },
      });
    }
    const byMedId = new Map<string, MedicationAdministration[]>();
    for (const a of administrations) {
      const arr = byMedId.get(a.patient_medication_id) ?? [];
      arr.push(a);
      byMedId.set(a.patient_medication_id, arr);
    }
    if (auditContext?.userId) {
      try {
        await this.auditLogService.log({
          userId: auditContext.userId,
          action: 'READ',
          resourceType: 'PATIENT_MEDICATION',
          resourceId: patientId,
          description: 'List patient medications',
          ipAddress: auditContext.ipAddress,
          userAgent: auditContext.userAgent,
          status: 'success',
          metadata: { count: list.length },
        });
      } catch {
        // ignore audit failure
      }
    }
    return list.map((m) =>
      this.toResponse(m, byMedId.get(m.id) ?? []),
    );
  }

  async create(
    patientId: string,
    dto: CreateMedicationDto,
    auditContext?: MedicationAuditContext,
  ): Promise<MedicationResponse> {
    const med = this.medicationRepository.create({
      patient_id: patientId,
      name: dto.name,
      dosage: dto.dosage ?? null,
      form: dto.form ?? null,
      frequency: dto.frequency ?? null,
      prescribed_by: dto.prescribedBy ?? null,
      instructions: dto.instructions ?? null,
      start_date: dto.startDate ? new Date(dto.startDate) : null,
      on_hand: dto.onHand ?? 0,
      total_quantity: dto.totalQuantity ?? 1,
      unit: dto.unit ?? null,
    });
    const saved = await this.medicationRepository.save(med);
    const timeSlots = dto.timeSlots ?? [];
    for (let i = 0; i < timeSlots.length; i++) {
      const slot = this.timeSlotRepository.create({
        patient_medication_id: saved.id,
        time_of_day: timeSlots[i],
        sort_order: i,
      });
      await this.timeSlotRepository.save(slot);
    }
    const withSlots = await this.medicationRepository.findOne({
      where: { id: saved.id },
      relations: ['time_slots'],
    });
    if (auditContext?.userId) {
      try {
        await this.auditLogService.log({
          userId: auditContext.userId,
          action: 'CREATE',
          resourceType: 'PATIENT_MEDICATION',
          resourceId: saved.id,
          description: 'Create patient medication',
          ipAddress: auditContext.ipAddress,
          userAgent: auditContext.userAgent,
          status: 'success',
        });
      } catch {
        // ignore audit failure
      }
    }
    return this.toResponse(withSlots ?? saved);
  }

  async updateInventory(
    patientId: string,
    medicationId: string,
    dto: UpdateMedicationInventoryDto,
    auditContext?: MedicationAuditContext,
  ): Promise<MedicationInventoryResponse> {
    const med = await this.medicationRepository.findOne({
      where: { id: medicationId, patient_id: patientId, deleted_at: IsNull() },
    });
    if (!med) {
      throw new NotFoundException('Medication not found');
    }
    if (dto.onHand !== undefined) med.on_hand = dto.onHand;
    if (dto.totalQuantity !== undefined) med.total_quantity = dto.totalQuantity;
    if (dto.unit !== undefined) med.unit = dto.unit;
    await this.medicationRepository.save(med);
    if (auditContext?.userId) {
      try {
        await this.auditLogService.log({
          userId: auditContext.userId,
          action: 'UPDATE',
          resourceType: 'PATIENT_MEDICATION',
          resourceId: medicationId,
          description: 'Update medication inventory',
          ipAddress: auditContext.ipAddress,
          userAgent: auditContext.userAgent,
          status: 'success',
        });
      } catch {
        // ignore audit failure
      }
    }
    return this.toInventoryResponse(med);
  }

  async update(
    patientId: string,
    medicationId: string,
    dto: UpdateMedicationDto,
    auditContext?: MedicationAuditContext,
  ): Promise<MedicationResponse> {
    const med = await this.medicationRepository.findOne({
      where: { id: medicationId, patient_id: patientId, deleted_at: IsNull() },
      relations: ['time_slots'],
    });
    if (!med) {
      throw new NotFoundException('Medication not found');
    }
    if (dto.name !== undefined) med.name = dto.name;
    if (dto.dosage !== undefined) med.dosage = dto.dosage;
    if (dto.form !== undefined) med.form = dto.form;
    if (dto.frequency !== undefined) med.frequency = dto.frequency;
    if (dto.prescribedBy !== undefined) med.prescribed_by = dto.prescribedBy;
    if (dto.instructions !== undefined) med.instructions = dto.instructions;
    if (dto.startDate !== undefined) med.start_date = dto.startDate ? new Date(dto.startDate) : null;
    if (dto.onHand !== undefined) med.on_hand = dto.onHand;
    if (dto.totalQuantity !== undefined) med.total_quantity = dto.totalQuantity;
    if (dto.unit !== undefined) med.unit = dto.unit;
    await this.medicationRepository.save(med);

    if (dto.timeSlots !== undefined) {
      await this.timeSlotRepository.delete({ patient_medication_id: medicationId });
      for (let i = 0; i < dto.timeSlots.length; i++) {
        const slot = this.timeSlotRepository.create({
          patient_medication_id: medicationId,
          time_of_day: dto.timeSlots[i],
          sort_order: i,
        });
        await this.timeSlotRepository.save(slot);
      }
    }

    const updated = await this.medicationRepository.findOne({
      where: { id: medicationId },
      relations: ['time_slots'],
    });
    if (auditContext?.userId) {
      try {
        await this.auditLogService.log({
          userId: auditContext.userId,
          action: 'UPDATE',
          resourceType: 'PATIENT_MEDICATION',
          resourceId: medicationId,
          description: 'Update patient medication',
          ipAddress: auditContext.ipAddress,
          userAgent: auditContext.userAgent,
          status: 'success',
        });
      } catch {
        // ignore audit failure
      }
    }
    return this.toResponse(updated ?? med);
  }

  async markAsTaken(
    patientId: string,
    medicationId: string,
    dto: MarkMedicationTakenDto,
    auditContext?: MedicationAuditContext,
  ): Promise<TakenForDateItem> {
    const med = await this.medicationRepository.findOne({
      where: { id: medicationId, patient_id: patientId, deleted_at: IsNull() },
      relations: ['time_slots'],
    });
    if (!med) {
      throw new NotFoundException('Medication not found');
    }
    const timeSlotStrings = (med.time_slots ?? [])
      .slice()
      .sort((a, b) => a.sort_order - b.sort_order)
      .map((s) => s.time_of_day ?? '');
    if (!timeSlotStrings.includes(dto.timeSlot)) {
      throw new BadRequestException(
        `Time slot "${dto.timeSlot}" is not configured for this medication`,
      );
    }
    const scheduledDate = new Date(dto.date);
    if (Number.isNaN(scheduledDate.getTime())) {
      throw new BadRequestException('Invalid date');
    }
    const dateOnly = dto.date.slice(0, 10);

    let admin = await this.administrationRepository.findOne({
      where: {
        patient_medication_id: medicationId,
        scheduled_date: new Date(dateOnly),
        time_slot: dto.timeSlot,
      },
    });
    const now = new Date();
    const isNew = !admin;
    if (admin) {
      admin.taken = true;
      admin.taken_at = now;
      admin.method = 'manual';
      admin.recorded_by_user_id = patientId;
      await this.administrationRepository.save(admin);
    } else {
      admin = this.administrationRepository.create({
        patient_medication_id: medicationId,
        scheduled_date: new Date(dateOnly),
        time_slot: dto.timeSlot,
        taken: true,
        taken_at: now,
        method: 'manual',
        recorded_by_user_id: patientId,
      });
      admin = await this.administrationRepository.save(admin);
    }

    if (auditContext?.userId) {
      try {
        await this.auditLogService.log({
          userId: auditContext.userId,
          action: isNew ? 'CREATE' : 'UPDATE',
          resourceType: 'MEDICATION_ADMINISTRATION',
          resourceId: admin.id,
          description: 'Mark medication as taken',
          ipAddress: auditContext.ipAddress,
          userAgent: auditContext.userAgent,
          status: 'success',
          metadata: { medicationId, date: dateOnly, timeSlot: dto.timeSlot },
        });
      } catch {
        // ignore audit failure
      }
    }

    return {
      timeSlot: admin.time_slot ?? '',
      taken: admin.taken,
      recordedAt: admin.taken_at ? admin.taken_at.toISOString() : null,
    };
  }

  async remove(
    patientId: string,
    medicationId: string,
    auditContext?: MedicationAuditContext,
  ): Promise<void> {
    const med = await this.medicationRepository.findOne({
      where: { id: medicationId, patient_id: patientId, deleted_at: IsNull() },
    });
    if (!med) {
      throw new NotFoundException('Medication not found');
    }
    med.deleted_at = new Date();
    await this.medicationRepository.save(med);
    if (auditContext?.userId) {
      try {
        await this.auditLogService.log({
          userId: auditContext.userId,
          action: 'DELETE',
          resourceType: 'PATIENT_MEDICATION',
          resourceId: medicationId,
          description: 'Soft delete patient medication',
          ipAddress: auditContext.ipAddress,
          userAgent: auditContext.userAgent,
          status: 'success',
        });
      } catch {
        // ignore audit failure
      }
    }
  }
}
