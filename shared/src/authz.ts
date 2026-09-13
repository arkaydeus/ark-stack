export const roles = ["owner", "operator", "viewer"] as const;
export type Role = (typeof roles)[number];

export type Access = {
  userId: string;
  role: Role;
  projectIds: string[];
  domainIds: string[];
};

export const privilegedActions = [
  "role.grant",
  "secret.reveal",
  "resource.delete",
  "restore.overwrite",
  "exposure.public",
  "credential.rotate",
  "platform.update",
] as const;

export type PrivilegedAction = (typeof privilegedActions)[number];

const roleRank: Record<Role, number> = { viewer: 1, operator: 2, owner: 3 };

export function hasRole(access: Access, minimum: Role) {
  return roleRank[access.role] >= roleRank[minimum];
}

export function canViewProject(access: Access, projectId: string) {
  return access.role === "owner" || access.projectIds.includes(projectId);
}

export function canManageDomain(access: Access, domainId: string) {
  return access.role === "owner" || (hasRole(access, "operator") && access.domainIds.includes(domainId));
}

export function canMutate(access: Access) {
  return hasRole(access, "operator");
}

export function canAdminister(access: Access) {
  return access.role === "owner";
}

export function hasMfaAssurance(input: {
  twoFactorEnabled: boolean;
  mfaEnrolledAt: Date | null;
  sessionCreatedAt: Date;
}) {
  return (
    input.twoFactorEnabled &&
    input.mfaEnrolledAt !== null &&
    input.sessionCreatedAt.getTime() >= input.mfaEnrolledAt.getTime()
  );
}

export function hasRecentStepUp(authenticatedAt: Date, now = new Date(), windowMs = 30 * 60 * 1000) {
  return now.getTime() - authenticatedAt.getTime() <= windowMs;
}

export function assertPrivileged(access: Access, action: PrivilegedAction, stepUpAt: Date) {
  if (!canMutate(access)) throw new Error("This action requires an operator or owner.");
  if (action === "role.grant" && !canAdminister(access)) {
    throw new Error("Only an owner can grant roles.");
  }
  if (!hasRecentStepUp(stepUpAt)) {
    throw new Error("Re-authenticate to continue with this privileged action.");
  }
}

export function protectLastOwner(owners: number, targetRole: Role | null) {
  if (owners <= 1 && targetRole !== "owner") {
    throw new Error("The last active owner cannot be demoted or removed.");
  }
}
