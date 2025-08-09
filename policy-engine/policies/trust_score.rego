package authz

default trust_score = 50

default risk_level = "high"

score := result {
  s := 50
  s := s + (10 * bool_to_int(input.user.authenticated))
  s := s + (10 * bool_to_int(input.user.mfa.verified))
  s := s - (20 * bool_to_int(input.user.status != "active"))
  s := s + (5 * bool_to_int(count(input.user.roles) > 0))
  s := s + (5 * bool_to_int(input.device.status == "trusted"))
  s := s - (30 * bool_to_int(input.device.status == "compromised" or input.device.status == "suspicious"))
  s := s - (25 * bool_to_int(input.context.access_type == "emergency"))
  s := s + (5 * bool_to_int(input.context.high_risk_authorized))
  s := s + (5 * bool_to_int(startswith(input.context.ip_address, "10.")))
  result := clamp(s, 0, 100)
}

trust_score := score

risk_level := level {
  s := score
  level := "critical"
  level := if s >= 80 then "low" else if s >= 60 then "medium" else if s >= 40 then "high" else "critical"
}

bucket := b {
  s := score
  start := floor(s / 10) * 10
  end := start + 9
  b := sprintf("b%v-%v", [start, end])
}

bool_to_int(b) = out {
  b
  out := 1
} else = out {
  not b
  out := 0
}

clamp(x, min, max) = out {
  x < min
  out := min
} else = out {
  x > max
  out := max
} else = out {
  out := x
}



