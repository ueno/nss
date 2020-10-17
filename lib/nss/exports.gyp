# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
{
  'includes': [
    '../../coreconf/config.gypi'
  ],
  'targets': [
    {
      'target_name': 'lib_nss_exports',
      'type': 'none',
      'copies': [
        {
          'files': [
            'nss.h'
          ],
          'destination': '<(nss_public_dist_dir)/<(module)'
        },
        {
          'files': [
            'nssoptions.h',
            'nssprobes.h',
            '<(nssprobes_generated_h)',
            'nssrenam.h'
          ],
          'destination': '<(nss_private_dist_dir)/<(module)'
        }
      ],
      'conditions': [
        [ 'disable_dtrace!=1', {
          'actions': [
            {
              'msvs_cygwin_shell': 0,
              'action': [
                'dtrace',
                '-s',
                '<@(_inputs)',
                '-h',
                '-o',
                '<@(_outputs)',
              ],
              'inputs': [
                'nssprobes.d',
              ],
              'outputs': [
                '<(nssprobes_generated_h)'
              ],
              'action_name': 'generate_nssprobes_h'
            },
          ],
          'variables': {
            'nssprobes_generated_h': '<(INTERMEDIATE_DIR)/nssprobes_generated.h',
          }
        }],
      ]
    }
  ],
  'variables': {
    'module': 'nss'
  }
}
