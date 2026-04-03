package main

import future.keywords.in

# Refuser les conteneurs qui tournent en tant que root
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg := sprintf("Le conteneur '%s' doit avoir securityContext.runAsNonRoot = true", [container.name])
}

# Refuser les conteneurs sans runAsUser defini
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsUser
    msg := sprintf("Le conteneur '%s' doit definir securityContext.runAsUser (!= 0)", [container.name])
}

# Refuser les conteneurs qui autorisent l'escalade de privileges
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    container.securityContext.allowPrivilegeEscalation == true
    msg := sprintf("Le conteneur '%s' ne doit pas autoriser l'escalade de privileges", [container.name])
}
