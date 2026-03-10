import { ModelSerializer } from '../../../common/serializers/model.serializer';
import { Address } from '../entities';
import type { AddressInterface } from '../interfaces/address.interface';

export class AddressSerializer extends ModelSerializer {
  serialize(address: Address): AddressInterface {
    return {
      id: address.id,
      street: address.street,
      city: address.city,
      state: address.state,
      zipCode: address.zipCode,
      country: address.country,
      userId: address.userId,
      createdAt: address.createdAt,
      updatedAt: address.updatedAt,
    };
  }
}
