# Reporting
**The script captures the following information:**
  •	Entra privileged roles and their assigned users.
  •	Assignment status, including Active and Eligible assignments.
  •	Assignment details, including the assigner and assignment time.
  •	PIM activation activities, including approvals, justification, and activation time.
  •	Execution and tenant-level summary information.

**Upon execution, the script generates the following three files:**
  1.	**Entra-PrivilegedRoleAssignments.csv**: Contains the Entra role information and assigned users, including the assignment status, assigned by, and assignment time.
  2.	**Entra-PIMActivationHistory.csv**: Contains PIM role activation activities, including activation details, approvals, justification, and activation time.
  3.	**Entra-PIMReport-Summary.json**: Provides an execution summary, including tenant information, execution time, the total number of Active and Eligible assignments, and the location of the generated results.
