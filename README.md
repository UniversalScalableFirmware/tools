###########################
Tools for universal payload
###########################


pack_payload
============
  This tool can be used to pack a normal payload image into the universal
  payload image format

  * To print a universal payload image format::

    python pack_payload.py -i universal_payload_image

  * To pack a normal payload binary into universal payload image format::

    python pack_payload.py -i normal_payload_image -o universal_payload_image

  .. note::
    This tool currently only supports UEFI payload format.
