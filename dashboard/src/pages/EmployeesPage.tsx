import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";

import EmployeePicker from "../components/EmployeePicker";
import type { SelectedEmployee } from "../components/EmployeePicker";
import ErrorBanner from "../components/ErrorBanner";
import { api } from "../api/client";
import type { CreateEmployeeRequest, Employee, UpdateEmployeeRequest } from "../api/client";
import { useAuth } from "../auth";

export default function EmployeesPage() {
  const { can } = useAuth();
  const [employees, setEmployees] = useState<Employee[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [search, setSearch] = useState("");
  const [departmentFilter, setDepartmentFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  // Add Dialog
  const [isAddOpen, setIsAddOpen] = useState(false);
  /** Chosen from Entra ID, not typed. Null until somebody is picked. */
  const [addEmployee, setAddEmployee] = useState<SelectedEmployee | null>(null);
  const [addDept, setAddDept] = useState("");
  const [addTitle, setAddTitle] = useState("");
  const [addPhone, setAddPhone] = useState("");
  const [addBusy, setAddBusy] = useState(false);

  // Edit Dialog
  const [editingEmployee, setEditingEmployee] = useState<Employee | null>(null);
  const [editName, setEditName] = useState("");
  const [editEmail, setEditEmail] = useState("");
  const [editDept, setEditDept] = useState("");
  const [editTitle, setEditTitle] = useState("");
  const [editPhone, setEditPhone] = useState("");
  const [editStatus, setEditStatus] = useState<"active" | "suspended" | "offboarded">("active");
  const [editBusy, setEditBusy] = useState(false);

  // Notice banner
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const data = await api.listEmployees({
        q: search || undefined,
        department: departmentFilter || undefined,
        status: statusFilter || undefined,
      });
      setEmployees(data);
    } catch (caught) {
      setError(caught);
    }
  }, [search, departmentFilter, statusFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!addEmployee) return;
    setAddBusy(true);
    setError(null);
    try {
      const body: CreateEmployeeRequest = {
        // Name and address come from the directory rather than the keyboard,
        // so one person cannot become two records differing by a capital
        // letter or a missing surname.
        full_name: addEmployee.name,
        email: addEmployee.email,
        // The three Entra does not hold for this tenant. Department is empty on
        // all 92 accounts, so if it is wanted it has to be typed here.
        department: addDept.trim() || addEmployee.department || null,
        job_title: addTitle.trim() || null,
        phone: addPhone.trim() || null,
      };
      await api.createEmployee(body);
      setIsAddOpen(false);
      setAddEmployee(null);
      setAddDept("");
      setAddTitle("");
      setAddPhone("");
      setNotice(`Employee record created for ${body.full_name}.`);
      await load();
    } catch (caught) {
      setError(caught);
    } finally {
      setAddBusy(false);
    }
  }

  function openEdit(emp: Employee) {
    setEditingEmployee(emp);
    setEditName(emp.full_name);
    setEditEmail(emp.email);
    setEditDept(emp.department ?? "");
    setEditTitle(emp.job_title ?? "");
    setEditPhone(emp.phone ?? "");
    setEditStatus(emp.status);
  }

  async function handleUpdate(e: React.FormEvent) {
    e.preventDefault();
    if (!editingEmployee) return;
    setEditBusy(true);
    setError(null);
    try {
      const body: UpdateEmployeeRequest = {
        full_name: editName.trim(),
        email: editEmail.trim(),
        department: editDept.trim() || null,
        job_title: editTitle.trim() || null,
        phone: editPhone.trim() || null,
        status: editStatus,
      };
      await api.updateEmployee(editingEmployee.id, body);
      setEditingEmployee(null);
      setNotice(`Updated ${body.full_name}.`);
      await load();
    } catch (caught) {
      setError(caught);
    } finally {
      setEditBusy(false);
    }
  }

  async function handleDelete(emp: Employee) {
    if (!window.confirm(`Delete record for ${emp.full_name}?`)) return;
    setError(null);
    try {
      await api.deleteEmployee(emp.id);
      setNotice(`Deleted record for ${emp.full_name}.`);
      await load();
    } catch (caught) {
      setError(caught);
    }
  }

  const departments = Array.from(
    new Set(employees.map((e) => e.department).filter((d): d is string => Boolean(d)))
  ).sort();

  return (
    <section>
      <div className="page-head">
        <div>
          <h1>Employees</h1>
          <p className="muted">
            People who hold, or have held, a company laptop. Not the full staff list —
            that lives in Microsoft Entra ID and is read directly when you issue a
            token. A record appears here once somebody is issued one.
          </p>
        </div>
        {can("enrollment_token_manage") && (
          <button
            type="button"
            className="button primary"
            onClick={() => setIsAddOpen(true)}
          >
            + Add Employee
          </button>
        )}
      </div>

      <ErrorBanner error={error} />
      {notice && (
        <div className="banner ok" role="status">
          <p>{notice}</p>
        </div>
      )}

      {/* Filter controls */}
      <div className="filter-bar" style={{ display: "flex", gap: "0.75rem", marginBottom: "1rem" }}>
        <input
          type="search"
          placeholder="Search by name, email, or department…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ flex: 1 }}
        />
        <select
          value={departmentFilter}
          onChange={(e) => setDepartmentFilter(e.target.value)}
        >
          <option value="">All Departments</option>
          {departments.map((d) => (
            <option key={d} value={d}>
              {d}
            </option>
          ))}
        </select>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="">All Statuses</option>
          <option value="active">Active</option>
          <option value="suspended">Suspended</option>
          <option value="offboarded">Offboarded</option>
        </select>
      </div>

      {/* Employees Table */}
      <div className="card">
        {employees.length === 0 ? (
          /* Says why it is empty rather than just that it is. An empty list
             here reads as "the directory failed to load" unless it explains
             that records are created by issuing a token, not by syncing. */
          <p className="muted">
            Nobody has been issued a laptop yet. Records appear here when you create an
            enrollment token for someone on the{" "}
            <Link to="/enrollment">Enrollment</Link> page.
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Employee</th>
                <th>Email</th>
                <th>Department</th>
                <th>Phone</th>
                <th>Status</th>
                <th>Devices</th>
                <th style={{ textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {employees.map((emp) => (
                <tr key={emp.id}>
                  <td>
                    <strong>{emp.full_name}</strong>
                    {emp.job_title && (
                      <div className="muted small">{emp.job_title}</div>
                    )}
                  </td>
                  <td>{emp.email}</td>
                  <td>{emp.department ?? "—"}</td>
                  <td>{emp.phone ?? "—"}</td>
                  <td>
                    <span className={`pill ${emp.status === "active" ? "online" : "offline"}`}>
                      {emp.status}
                    </span>
                  </td>
                  <td>
                    {emp.assigned_device_count > 0 ? (
                      <Link
                        to={`/devices?q=${encodeURIComponent(emp.full_name)}`}
                        className="pill online"
                        style={{ textDecoration: "none" }}
                      >
                        {emp.assigned_device_count} assigned
                      </Link>
                    ) : (
                      <span className="muted">0</span>
                    )}
                  </td>
                  <td style={{ textAlign: "right" }}>
                    {can("enrollment_token_manage") && (
                      <div style={{ display: "inline-flex", gap: "0.5rem" }}>
                        <button
                          type="button"
                          className="button subtle small"
                          onClick={() => openEdit(emp)}
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          className="button subtle small"
                          onClick={() => handleDelete(emp)}
                        >
                          Delete
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Add Employee Dialog */}
      {isAddOpen && (
        <div className="dialog-overlay">
          <div className="dialog card">
            <h2>Add an employee record</h2>
            <form onSubmit={handleCreate}>
              {/* The picker, not two text boxes. Typing a name and address by
                  hand for somebody already in Entra ID is how you get two
                  records for one person. The remaining fields stay free text
                  because Entra holds none of them for this tenant. */}
              <div className="form-group">
                <EmployeePicker
                  value={addEmployee}
                  onChange={(next) => {
                    setAddEmployee(next);
                    // Prefill from the directory where it has anything, but
                    // leave what the admin typed alone.
                    if (next?.department && !addDept) setAddDept(next.department);
                  }}
                  disabled={addBusy}
                  label="Who is this record for?"
                  chosenLabel="Employee"
                />
              </div>

              {addEmployee?.employeeId && (
                <p className="banner warn" role="status">
                  {addEmployee.name} already has a record here. Close this and edit it
                  instead — adding again will be refused.
                </p>
              )}

              <div className="form-group">
                <label htmlFor="add-dept">Department</label>
                <input
                  id="add-dept"
                  type="text"
                  value={addDept}
                  onChange={(e) => setAddDept(e.target.value)}
                  placeholder="e.g. Engineering, Sales, HR"
                />
              </div>

              <div className="form-group">
                <label htmlFor="add-title">Job Title</label>
                <input
                  id="add-title"
                  type="text"
                  value={addTitle}
                  onChange={(e) => setAddTitle(e.target.value)}
                  placeholder="e.g. Staff Security Engineer"
                />
              </div>

              <div className="form-group">
                <label htmlFor="add-phone">Phone Number</label>
                <input
                  id="add-phone"
                  type="tel"
                  value={addPhone}
                  onChange={(e) => setAddPhone(e.target.value)}
                  placeholder="+1 (555) 019-2834"
                />
              </div>

              <div className="dialog-actions" style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem", marginTop: "1.25rem" }}>
                <button
                  type="button"
                  className="button"
                  onClick={() => setIsAddOpen(false)}
                  disabled={addBusy}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="button primary"
                  // Nothing to save until somebody is chosen, and saving a
                  // person who already has a record would only earn a 409.
                  disabled={addBusy || !addEmployee || Boolean(addEmployee.employeeId)}
                >
                  {addBusy ? "Saving…" : "Save Employee"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Employee Dialog */}
      {editingEmployee && (
        <div className="dialog-overlay">
          <div className="dialog card">
            <h2>Edit Employee: {editingEmployee.full_name}</h2>
            <form onSubmit={handleUpdate}>
              <div className="form-group">
                <label htmlFor="edit-name">Full Name *</label>
                <input
                  id="edit-name"
                  type="text"
                  required
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label htmlFor="edit-email">Work Email *</label>
                <input
                  id="edit-email"
                  type="email"
                  required
                  value={editEmail}
                  onChange={(e) => setEditEmail(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label htmlFor="edit-dept">Department</label>
                <input
                  id="edit-dept"
                  type="text"
                  value={editDept}
                  onChange={(e) => setEditDept(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label htmlFor="edit-title">Job Title</label>
                <input
                  id="edit-title"
                  type="text"
                  value={editTitle}
                  onChange={(e) => setEditTitle(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label htmlFor="edit-phone">Phone Number</label>
                <input
                  id="edit-phone"
                  type="tel"
                  value={editPhone}
                  onChange={(e) => setEditPhone(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label htmlFor="edit-status">Status</label>
                <select
                  id="edit-status"
                  value={editStatus}
                  onChange={(e) => setEditStatus(e.target.value as "active" | "suspended" | "offboarded")}
                >
                  <option value="active">Active</option>
                  <option value="suspended">Suspended</option>
                  <option value="offboarded">Offboarded</option>
                </select>
              </div>

              <div className="dialog-actions" style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem", marginTop: "1.25rem" }}>
                <button
                  type="button"
                  className="button"
                  onClick={() => setEditingEmployee(null)}
                  disabled={editBusy}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="button primary"
                  disabled={editBusy}
                >
                  {editBusy ? "Saving…" : "Update Employee"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </section>
  );
}

