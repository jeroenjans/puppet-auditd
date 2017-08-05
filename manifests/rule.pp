##  params:
##    content: Rule definition
##    order:   Relative order of this rule

define auditd::rule (
  $target  = 'undefined',
  $content = '',
  $order   = 10,
) {
  if $content == '' {
    $body = $name
  } else {
    $body = $content
  }

  if (!is_numeric($order) and !is_string($order))
  {
    fail('$order must be a string or an integer')
  }
  validate_string($body)

  if $::auditd::manage_audit_files {
    file { "/etc/audit/rules.d/${order}-${target}":
      ensure  => 'present',
      content => $content,
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
    }
  } else {
    concat::fragment { "auditd_fragment_${name}":
      target  => $target,
      order   => $order,
      content => $body,
    }
  }
}
