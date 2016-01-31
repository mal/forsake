{
    'variables': {
      # Default for this variable, to get the right behavior for
      # Node versions <= 0.6.*. or NW.JS or Mac OS X 10.11+
      'node_shared_openssl%': 'true'
    },
    'targets': [{
        'target_name': 'forsaken',
        'sources': [
            'src/forsaken.cc',
            'src/ssl.cc'
        ],
        'include_dirs': [
            "<!(node -e \"require('nan')\")"
        ],
        'cflags': [ '-O3' ],
        'conditions':
        [[
            'OS=="win"',
            {
                'conditions': [[
                    'target_arch=="x64"',
                    {
                        'variables': {
                            'openssl_root%': 'C:/OpenSSL-Win64'
                        }
                    },
                    {
                        'variables': {
                            'openssl_root%': 'C:/OpenSSL-Win32'
                        }
                    }
                ]],
                'libraries': [
                    '-l<(openssl_root)/lib/libeay32.lib',
                    '-l<(openssl_root)/lib/ssleay32.lib'
                ],
                'include_dirs': [
                    '<(openssl_root)/include'
                ]
            }, { # OS!="win"
                'conditions': [[
                    'node_shared_openssl=="false"',
                    {
                      'include_dirs': [
                        '<(node_root_dir)/deps/openssl/openssl/include'
                      ]
                    }
                ]]
            }
        ]]
    }]
}
