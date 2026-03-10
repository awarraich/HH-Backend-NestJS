import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Address } from './entities/address.entity';
import { AddressSerializer } from './serializers/address.serializer';
import type { CreateAddressDto } from './dto/create-address.dto';
import type { AddressInterface } from './interfaces/address.interface';

@Injectable()
export class AddressesService {
  private addressSerializer = new AddressSerializer();

  constructor(
    @InjectRepository(Address)
    private addressesRepository: Repository<Address>,
  ) {}

  async findAll(): Promise<AddressInterface[]> {
    const addresses = await this.addressesRepository.find();
    return this.addressSerializer.serializeMany(addresses) as AddressInterface[];
  }

  async create(createAddressDto: CreateAddressDto): Promise<AddressInterface> {
    const address = this.addressesRepository.create({
      ...createAddressDto,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    const saved = await this.addressesRepository.save(address);
    // save() can return an array if multiple entities are saved, but we're saving one
    const savedAddress = (Array.isArray(saved) ? saved[0] : saved) as Address;
    return this.addressSerializer.serialize(savedAddress);
  }
}
