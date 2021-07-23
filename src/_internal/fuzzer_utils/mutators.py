# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Fuzzing mutators."""

import random
import struct

DEFAULT_MIN_MUTATIONS = 1
DEFAULT_MAX_MUTATIONS = 20


def get_pack_format_and_mask_for_num_bytes(num_bytes,
                                           signed=False,
                                           little_endian=True):
  """Return the struct pack format and bit mask for the integer values of size
  |num_bytes|."""
  if num_bytes == 1:
    pack_fmt = 'B'
    mask = (1 << 8) - 1
  elif num_bytes == 2:
    pack_fmt = 'H'
    mask = (1 << 16) - 1
  elif num_bytes == 4:
    pack_fmt = 'I'
    mask = (1 << 32) - 1
  elif num_bytes == 8:
    pack_fmt = 'Q'
    mask = (1 << 64) - 1
  else:
    raise ValueError

  if signed:
    pack_fmt = pack_fmt.lower()

  if num_bytes > 1:
    if little_endian:
      pack_fmt = '<' + pack_fmt
    else:
      pack_fmt = '>' + pack_fmt

  return pack_fmt, mask


class MutatorPrimitive(object):
  """A mutator primitive."""

  def __init__(self, ratio=0.0, up_to_ratio=False):
    self.ratio = ratio
    self.up_to_ratio = up_to_ratio

  def mutate_ratio(self):
    """Get the mutation ratio."""
    if self.up_to_ratio:
      return self.ratio * random.random()

    return self.ratio


class BitFlipper(MutatorPrimitive):
  """Flip random bits until the given ratio is satisfied."""

  def __init__(self, ratio=0.0, up_to_ratio=False, contiguous_flips=1):
    super(BitFlipper, self).__init__(ratio, up_to_ratio)
    self.contiguous_flips = contiguous_flips

  def mutate(self, buf):
    """Mutator function."""
    bits_flipped = 0

    num_bits = len(buf) * 8
    ratio = self.mutate_ratio()

    while bits_flipped < int(ratio * len(buf)):
      n = random.randint(0, num_bits - 1)
      for i in range(n, min(num_bits, n + self.contiguous_flips)):
        buf[i // 8] ^= (1 << (i % 8))
        bits_flipped += 1


class BinaryValueAdder(MutatorPrimitive):
  """Add random value to binary values of size |num_bytes| in the buffer until
  the given ratio is satisfied."""

  def __init__(self,
               ratio=0.0,
               up_to_ratio=False,
               num_bytes=1,
               add_range=(-35, 35)):
    super(BinaryValueAdder, self).__init__(ratio, up_to_ratio)
    self.num_bytes = num_bytes
    self.add_range = add_range

    # Assume little endian
    self.pack_fmt, self.mask = get_pack_format_and_mask_for_num_bytes(
        num_bytes, signed=False, little_endian=True)

  def mutate(self, buf):
    """Mutator function."""
    num_choices = len(buf) // self.num_bytes
    changed = 0
    ratio = self.mutate_ratio()

    while changed < int(ratio * num_choices):
      n = random.randint(0, num_choices - 1)
      buf_start = n * self.num_bytes
      buf_end = buf_start + self.num_bytes
      orig = struct.unpack(self.pack_fmt, buf[buf_start:buf_end])[0]

      rand_val = random.randint(self.add_range[0], self.add_range[1])
      new_val = (orig + rand_val) & self.mask
      buf[buf_start:buf_end] = bytearray(struct.pack(self.pack_fmt, new_val))
      changed += 1


class ByteRemover(MutatorPrimitive):
  """Randomly delete |num_bytes| bytes at a time until the ratio is
  satisfied."""

  def __init__(self, ratio=0.0, up_to_ratio=False, num_bytes=1):
    super(ByteRemover, self).__init__(ratio, up_to_ratio)
    self.num_bytes = num_bytes

  def mutate(self, buf):
    """Mutator function."""
    num_choices = len(buf) // self.num_bytes
    changed = 0
    ratio = self.mutate_ratio()

    while changed < int(ratio * len(buf)):
      n = random.randint(0, num_choices - 1)

      del_start = n * self.num_bytes
      del_end = del_start + self.num_bytes

      del buf[del_start:del_end]
      changed += 1


class ByteInserter(MutatorPrimitive):
  """Randomly insert |num_bytes| at a time until the ratio is satisfied."""

  def __init__(self, ratio=0.0, up_to_ratio=False, num_bytes=1):
    super(ByteInserter, self).__init__(ratio, up_to_ratio)
    self.num_bytes = num_bytes

  def mutate(self, buf):
    """Mutator function."""
    num_choices = len(buf) + 1
    inserted = 0
    ratio = self.mutate_ratio()

    while inserted < int(ratio * num_choices):
      # TODO(ochang): context aware
      insert_pos = random.randint(0, num_choices)
      rand_bytes = [random.randint(0, 255) for _ in range(self.num_bytes)]
      buf[insert_pos:insert_pos] = bytearray(rand_bytes)
      inserted += self.num_bytes


class ChunkCopier(MutatorPrimitive):
  """Randomly copy |chunk_ratio * len(buf)| bytes at a time from one location
  to another until the ratio is satisfied."""

  def __init__(self, ratio=0.0, up_to_ratio=False, chunk_ratio=0.1):
    super(ChunkCopier, self).__init__(ratio, up_to_ratio)
    self.chunk_ratio = chunk_ratio

  def mutate(self, buf):
    """Mutator function."""
    changed = 0
    ratio = self.mutate_ratio()
    chunk_size = int(self.chunk_ratio * len(buf))

    while changed < int(len(buf) * ratio):
      copy_from = random.randint(0, len(buf) - chunk_size)
      copy_to = random.randint(0, len(buf) - chunk_size)
      buf[copy_to:copy_to + chunk_size] = buf[copy_from:copy_from + chunk_size]

      changed += chunk_size


class SpecialIntReplacer(MutatorPrimitive):
  """Write special integer values (such as 0, INT_MIN, INT_MAX) of size
  |num_bytes| to random locations in the buffer."""

  def __init__(self, ratio=0.0, up_to_ratio=False, num_bytes=1):
    super(SpecialIntReplacer, self).__init__(ratio, up_to_ratio)
    self.num_bytes = num_bytes

    self.pack_fmt = get_pack_format_and_mask_for_num_bytes(
        num_bytes, signed=False, little_endian=True)[0]

  def mutate(self, buf):
    """Mutator function."""
    num_choices = len(buf) // self.num_bytes
    changed = 0

    # Unsigned representations of signed values
    signed_minimum = 1 << (8 * self.num_bytes - 1)
    signed_maximum = signed_minimum - 1

    # For calculation of values closed to signed minimum/maximum
    max_diff = 1 << (4 * self.num_bytes)

    special_ints = [
        struct.pack(self.pack_fmt, 0),
        # signed minimum
        struct.pack(self.pack_fmt, signed_minimum),
        # value close to signed minimum
        struct.pack(self.pack_fmt,
                    signed_minimum + random.randint(1, max_diff)),
        # signed maximum
        struct.pack(self.pack_fmt, signed_maximum),
        # value close to signed maximum
        struct.pack(self.pack_fmt,
                    signed_maximum - random.randint(1, max_diff)),
        # -1 or unsigned maximum
        struct.pack(self.pack_fmt, (1 << (8 * self.num_bytes)) - 1)
    ]

    ratio = self.mutate_ratio()
    while changed < int(ratio * num_choices):
      n = random.randint(0, num_choices - 1)
      buf_start = n * self.num_bytes
      buf_end = buf_start + self.num_bytes
      buf[buf_start:buf_end] = random.sample(special_ints, 1)[0]
      changed += 1


class SignFlipper(MutatorPrimitive):
  """Flip signs of random integer values of size |num_byte| until the ratio is
  satisfied."""

  def __init__(self, ratio=0.0, up_to_ratio=False, num_bytes=1):
    super(SignFlipper, self).__init__(ratio, up_to_ratio)
    self.num_bytes = num_bytes

    self.pack_fmt, self.mask = get_pack_format_and_mask_for_num_bytes(
        num_bytes, signed=True, little_endian=True)

  def mutate(self, buf):
    """Mutator function."""
    num_choices = len(buf) // self.num_bytes
    changed = 0

    ratio = self.mutate_ratio()
    while changed < int(ratio * num_choices):
      n = random.randint(0, num_choices - 1)
      buf_start = n * self.num_bytes
      buf_end = buf_start + self.num_bytes

      original_value = struct.unpack(self.pack_fmt, buf[buf_start:buf_end])[0]
      buf[buf_start:buf_end] = struct.pack(self.pack_fmt.upper(),
                                           (-original_value) & self.mask)
      changed += 1


class Truncator(MutatorPrimitive):
  """Truncate the buffer to a given ratio."""

  def mutate(self, buf):
    """Mutator function."""
    orig_len = len(buf)
    new_len = int(random.random() * self.mutate_ratio() * orig_len)
    del buf[new_len:]


class CombinedMutator(object):
  """Combination of mutator primitives."""

  def __init__(self, mutators=None, num_mutations_choices=None):
    if num_mutations_choices is None:
      num_mutations_choices = list(
          range(DEFAULT_MIN_MUTATIONS, DEFAULT_MAX_MUTATIONS + 1))
    self.mutators = []
    if mutators is not None:
      for mutator in mutators:
        self.mutators.append({'mutator': mutator[0], 'weight': mutator[1]})
    self.num_mutations_choices = num_mutations_choices

  def add_mutator(self, mutator, weight):
    """Add a mutator."""
    self.mutators.append({'mutator': mutator, 'weight': weight})

  def mutate(self, buf):
    """Mutator function."""
    num_mutations = random.sample(self.num_mutations_choices, 1)[0]
    for _ in range(num_mutations):
      mutator = self.choose_mutator()
      mutator.mutate(buf)

  def choose_mutator(self):
    """Choose a mutator."""
    total_weight = sum([x['weight'] for x in self.mutators])
    n = total_weight * random.random()
    cur = 0.0
    for choice in self.mutators:
      cur += choice['weight']
      if cur > n:
        return choice['mutator']

    return self.mutators[-1]['mutator']
