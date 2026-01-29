import {
  Injectable,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreditPackage } from './entities/credit-package.entity';
import { CreateCreditPackageDto } from './dto/create-credit-package.dto';
import { UpdateCreditPackageDto } from './dto/update-credit-package.dto';
import { QueryCreditPackageDto } from './dto/query-credit-package.dto';
import { CreditPackageSerializer } from './serializers/credit-package.serializer';

@Injectable()
export class CreditPackagesService {
  private creditPackageSerializer = new CreditPackageSerializer();

  constructor(
    @InjectRepository(CreditPackage)
    private creditPackagesRepository: Repository<CreditPackage>,
  ) {}

  async create(
    createCreditPackageDto: CreateCreditPackageDto,
    userId: string,
  ): Promise<any> {
    // Check if stripe_price_id already exists
    const existingPackage = await this.creditPackagesRepository.findOne({
      where: { stripe_price_id: createCreditPackageDto.stripe_price_id },
    });

    if (existingPackage) {
      throw new BadRequestException(
        'A credit package with this Stripe price ID already exists',
      );
    }

    const creditPackage = this.creditPackagesRepository.create({
      ...createCreditPackageDto,
      is_active: createCreditPackageDto.is_active ?? true,
    });

    const saved = await this.creditPackagesRepository.save(creditPackage);
    return this.creditPackageSerializer.serialize(saved);
  }

  async findAll(queryDto: QueryCreditPackageDto): Promise<{
    data: any[];
    total: number;
    page: number;
    limit: number;
  }> {
    const { is_active, page = 1, limit = 20 } = queryDto;
    const skip = (page - 1) * limit;

    const queryBuilder = this.creditPackagesRepository.createQueryBuilder(
      'credit_package',
    );

    if (is_active !== undefined) {
      queryBuilder.where('credit_package.is_active = :is_active', {
        is_active,
      });
    }

    queryBuilder.orderBy('credit_package.created_at', 'DESC');
    queryBuilder.skip(skip).take(limit);

    const [creditPackages, total] = await queryBuilder.getManyAndCount();

    return {
      data: this.creditPackageSerializer.serializeMany(creditPackages),
      total,
      page,
      limit,
    };
  }

  async findOne(id: string): Promise<any> {
    const creditPackage = await this.creditPackagesRepository.findOne({
      where: { id },
    });

    if (!creditPackage) {
      throw new NotFoundException(`Credit package with ID ${id} not found`);
    }

    return this.creditPackageSerializer.serialize(creditPackage);
  }

  async update(
    id: string,
    updateCreditPackageDto: UpdateCreditPackageDto,
    userId: string,
  ): Promise<any> {
    const creditPackage = await this.creditPackagesRepository.findOne({
      where: { id },
    });

    if (!creditPackage) {
      throw new NotFoundException(`Credit package with ID ${id} not found`);
    }

    // Check if stripe_price_id is being updated and if it already exists
    if (
      updateCreditPackageDto.stripe_price_id &&
      updateCreditPackageDto.stripe_price_id !== creditPackage.stripe_price_id
    ) {
      const existingPackage = await this.creditPackagesRepository.findOne({
        where: { stripe_price_id: updateCreditPackageDto.stripe_price_id },
      });

      if (existingPackage) {
        throw new BadRequestException(
          'A credit package with this Stripe price ID already exists',
        );
      }
    }

    Object.assign(creditPackage, updateCreditPackageDto);
    const updated = await this.creditPackagesRepository.save(creditPackage);

    return this.creditPackageSerializer.serialize(updated);
  }

  async remove(id: string, userId: string): Promise<void> {
    const creditPackage = await this.creditPackagesRepository.findOne({
      where: { id },
    });

    if (!creditPackage) {
      throw new NotFoundException(`Credit package with ID ${id} not found`);
    }

    await this.creditPackagesRepository.remove(creditPackage);
  }
}

