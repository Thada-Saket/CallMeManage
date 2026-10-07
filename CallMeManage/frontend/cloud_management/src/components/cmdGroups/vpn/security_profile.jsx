import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import { runDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { parseSecurityTunnels, findTunnelsUsingProfile } from "./parseSecurityTunnels";
import { parseSecurityProfiles } from "./parseSecurityProfiles";
import { describeRemoval } from "./securityProfileObjects";
import SecurityProfileFormModal from "./security_profileFormModal";
import CiscoIkev2Tables from "./ciscoIkev2Tables";
import { parseCiscoIkev2Objects } from "./ciscoIkev2Objects";
import Edit_Result from "../../commandResult/edit_command_result";
import PageTabs from "../../common/PageTabs";

const CISCO_SECURITY_TABS = [
  { id: "proposal", label: "IKEv2 Proposal" },
  { id: "policy", label: "IKEv2 Policy" },
  { id: "profile", label: "Security Profile" },
];

export default function SecurityProfile({ devId, vendor }) {
  const isJuniper = vendor === "juniper";
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_security_profile_information");
  // (bug 67) ต้องรู้ว่า profile ไหนมี tunnel ผูกอยู่ก่อนจะให้ลบ/เปลี่ยนชื่อได้
  // Cisco ไม่ยอมให้ลบ crypto object ที่ยัง in-use และจะ "ค้างไม่ตอบ" แทนที่จะตอบ
  // rpc-error (เจอจริงในผลทดสอบข้อ 5.3.1: อุปกรณ์เงียบ 20 วินาที -> session ถูกตัด ->
  // 503 -> 409 วนไม่จบ) ส่วนเคสเปลี่ยนชื่อจะเหลือ object เก่าค้าง 8 ตัวปนกับของใหม่
  // จน tunnel ขึ้นไม่ได้ (ข้อ 5.2.4) - กันไว้ตั้งแต่หน้าเว็บดีกว่าปล่อยให้ยิงไปแล้วพัง
  const { data: tunnelData, error: tunnelError } = getDeviceInformation(devId, "get_security_tunnel_information");
  const [formMode, setFormMode] = useState(null); // null | "create" | "edit"
  const [selectedName, setSelectedName] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");
  const [ciscoIkev2View, setCiscoIkev2View] = useState(null);
  const [activeTab, setActiveTab] = useState("proposal"); // "proposal" | "policy" | "profile"

  function handleSaved() {
    setFormMode(null);
    setSelectedName(null);
    refetch();
  }

  // profile ที่ระบบสร้างเอง (ชื่อตามแบบแผน) ใช้ remove_security_profile ที่ derive ชื่อ object ทั้งชุดจากชื่อ
  // profile ซึ่งตรวจบนอุปกรณ์จริงมาแล้ว - profile ที่มีอยู่บนอุปกรณ์อยู่ก่อน (ตั้งจาก CLI/ติดมาก่อน onboard)
  // ต้องลบได้เท่ากัน แต่ใช้ **ชื่อ object จริง** ที่ parser ไล่มาให้ (ไม่ derive) และไม่แตะ object ที่ profile
  // อื่นใช้ร่วมอยู่ (ผู้ใช้ยืนยัน 21 ก.ย. 2026 ว่าของจากอุปกรณ์ต้องแก้/ลบได้ ไม่ใช่เข้ามาได้อย่างเดียว)
  async function handleConfirmDelete(profile) {
    setDeleting(true);
    setDeleteError("");
    try {
      if (profile.managed) {
        // (ระลอก C1) เดิม Cisco รื้อทีละ object 6 คำสั่ง ถ้าพังกลางทางจะเหลือ object ค้างที่ผู้ใช้มองไม่เห็น -
        // remove_security_profile รื้อทั้งชุดใน RPC เดียวทั้ง 2 ยี่ห้อ จึงเรียกตัวเดียวกันได้
        await runDeviceCommand(devId, "remove_security_profile", { name: profile.name });
      } else {
        if (!profile.real?.removal?.params) throw new Error("Cannot read object names for this Profile from device, unable to determine what to delete");
        await runDeviceCommand(devId, profile.real.removal.command, profile.real.removal.params);
      }
      setShowDeleteConfirm(false);
      setSelectedName(null);
      refetch();
    } catch (err) {
      setDeleteError(err.detail || err.message || "Failed to delete Security Profile");
    } finally {
      setDeleting(false);
    }
  }

  if (loading && !data) return <div className="center-loading">Fetching Security Profile information...</div>;

  const profiles = data?.normalized ? parseSecurityProfiles(data.result) : null;
  const ciscoIkev2Objects = !isJuniper && data?.normalized ? parseCiscoIkev2Objects(data.result) : null;
  const selectedProfile = profiles?.find((profile) => profile.name === selectedName) || null;

  // (bug 67) tunnel ที่ผูกกับ profile ที่เลือกอยู่ - ถ้ามีแม้แต่ตัวเดียวห้ามลบ/เปลี่ยนชื่อ
  const tunnels = tunnelData?.normalized ? parseSecurityTunnels(tunnelData.result) : null;
  // (bug 67 ต่อ) **"ยังไม่รู้" ต้องไม่ถูกนับเป็น "ไม่มี tunnel ผูกอยู่"**
  //
  // tunnels เป็น null ได้ 3 ทาง: ยังโหลดไม่เสร็จ (2 คำสั่งยิงขนานกัน ตารางขึ้นได้ก่อนเสมอ),
  // ดึงข้อมูลไม่สำเร็จ, หรือ parse ไม่ผ่าน - ทั้ง 3 ทางแปลว่าเรายังตอบไม่ได้ว่า profile นี้
  // มีใครใช้อยู่ไหม ไม่ใช่ว่าไม่มีใครใช้ แต่ findTunnelsUsingProfile(null, ...) คืน []
  // เหมือนกรณี "ไม่มีเลย" เป๊ะ ๆ เดิมจึงปลดล็อกปุ่มลบและช่องชื่อให้ทันที = ด่านที่ตั้งไว้กัน
  // bug 67 หายไปเงียบ ๆ ในจังหวะที่อันตรายที่สุด (Cisco จะค้างไม่ตอบแทนที่จะตอบ rpc-error
  // เมื่อถูกสั่งลบ crypto object ที่ยัง in-use - ผลทดสอบข้อ 5.3.1: เงียบ 20 วิ -> session
  // ถูกตัด -> 503 -> 409 วนไม่จบ ส่วนเคสเปลี่ยนชื่อเหลือ object เก่าค้าง 8 ตัวจน tunnel
  // ขึ้นไม่ได้ ข้อ 5.2.4)
  const bindingUnknown = tunnels === null;
  const boundTunnels = selectedName ? findTunnelsUsingProfile(tunnels, selectedName) : [];
  const isBound = boundTunnels.length > 0;
  // แถวที่ไม่ได้สร้างจากระบบ (ตั้งจาก CLI/ติดมาก่อน onboard) - **แก้และลบได้เท่ากับของที่ระบบสร้าง** แต่ทำงาน
  // กับชื่อ object จริง จึงโชว์ชื่อจริงให้ผู้ใช้เห็นว่ากำลังจะแตะอะไร (ไม่ใช้เป็นเงื่อนไขปิดปุ่ม)
  const isBrownfield = !!selectedProfile && !selectedProfile.managed;
  const boundMessage = isBound
    ? `${boundTunnels.join(", ")} is using this Security Profile - delete Tunnel before deleting Profile`
    : "";

  if (!isJuniper && ciscoIkev2View && ciscoIkev2Objects) {
    return (
      <div className="command-configuration">
        <CiscoIkev2Tables
          devId={devId}
        objects={ciscoIkev2Objects}
        refetch={refetch}
        refreshing={loading}
          view={ciscoIkev2View}
          setView={setCiscoIkev2View}
        />
      </div>
    );
  }

  return (
    <div className="command-configuration">
      {error && <DismissibleError message={error} onDismiss={clearError} />}

      {formMode ? (
        <SecurityProfileFormModal
          devId={devId}
          vendor={vendor}
          mode={formMode}
          editTarget={formMode === "edit" ? selectedProfile : null}
          onClose={() => setFormMode(null)}
          onSaved={handleSaved}
        />
      ) : profiles === null ? (
        data && (
          <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
        )
      ) : isJuniper ? (
        <>
          {/* (bug 67 ต่อ) ดึงรายการ tunnel ไม่สำเร็จ = ปุ่มลบกับการเปลี่ยนชื่อถูกปิดไว้ ต้องบอก
              ให้รู้ว่าทำไม ไม่งั้นผู้ใช้เจอปุ่มที่กดไม่ได้โดยไม่มีคำอธิบายและไม่มีทางรู้ว่าต้องทำอะไรต่อ
              (ตอนกำลังโหลดไม่ต้องขึ้นอะไร - แป๊บเดียวปุ่มก็ใช้ได้เอง) */}
          {tunnelError && (
            <div className="form-error">
              Unable to check if any Tunnel is using this Security Profile ({tunnelError}) - Delete and rename are disabled until data is retrieved
            </div>
          )}
          <section>
            <div className="ikev2-section-heading"><div><h3>Security Profile</h3></div></div>
            <div className="command-output-title">
              <Edit_Result
                featureName="Security Profile"
                selectedLabel={selectedProfile?.name || ""}
                extraWarning={
                  isBound
                    ? boundMessage
                    : isBrownfield
                      ? describeRemoval(selectedProfile.real)
                      : "Delete all associated IKEv2/IPsec objects in a single command"
                }
                canEdit={!!selectedName}
                canDelete={!!selectedName && !isBound && !bindingUnknown}
                showDeleteConfirm={showDeleteConfirm}
                deleting={deleting}
                deleteError={deleteError} onDismissDeleteError={() => setDeleteError("")}
                onNew={() => setFormMode("create")}
                onEditClick={() => setFormMode("edit")}
                onOpenDeleteConfirm={() => setShowDeleteConfirm(true)}
                onCancelDelete={() => setShowDeleteConfirm(false)}
                onConfirmDelete={() => handleConfirmDelete(selectedProfile)}
                refreshing={loading}
                onRefresh={refetch}
              />
            </div>

            {profiles.length === 0 ? (
              <div className="config-placeholder">No Security Profile configured</div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    {/* (bug 95) ตัด IPsec Encryption/Integrity/PFS ออก - เดิมโชว์เฉพาะฝั่ง IPsec
                        ทำให้ผู้ใช้เข้าใจว่านั่นคือ algorithm ทั้งหมดของ profile ทั้งที่ยังมีชั้น
                        IKEv2 ที่สำคัญไม่แพ้กันแต่ไม่ได้โชว์ - ข้อมูลครึ่งเดียวหลอกกว่าไม่มีข้อมูล
                        ผู้ใช้ตัดสินใจให้เหลือแค่ 3 คอลัมน์ที่ระบุตัว profile ได้ ส่วน algorithm
                        ทั้งสองชั้นไปดูตอนกดแก้ไข (bug 92 ทำให้ฟอร์มแก้ไขโชว์ค่าจริงแล้ว) */}
                    <th>Name</th>
                    <th>Peer IP</th>
                    <th>Mode</th>
                  </tr>
                </thead>
                <tbody>
                  {profiles.map((profile, index) => (
                    <tr
                      key={`${profile.name}-${index}`}
                      className={`row-clickable ${profile.name === selectedName ? "row-selected" : ""}`}
                      onClick={() => setSelectedName(profile.name === selectedName ? null : profile.name)}
                    >
                      <td>{profile.name || "-"}</td>
                      <td>{profile.peerIp || "-"}</td>
                      <td>{profile.mode}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </>
      ) : (
        <>
          <PageTabs
            tabs={CISCO_SECURITY_TABS}
            activeId={activeTab}
            onChange={setActiveTab}
          />
          {activeTab === "profile" && (
            <div role="tabpanel" id="tabpanel-profile" aria-labelledby="tab-profile">
              {/* (bug 67 ต่อ) ดึงรายการ tunnel ไม่สำเร็จ = ปุ่มลบกับการเปลี่ยนชื่อถูกปิดไว้ ต้องบอก
                  ให้รู้ว่าทำไม ไม่งั้นผู้ใช้เจอปุ่มที่กดไม่ได้โดยไม่มีคำอธิบายและไม่มีทางรู้ว่าต้องทำอะไรต่อ
                  (ตอนกำลังโหลดไม่ต้องขึ้นอะไร - แป๊บเดียวปุ่มก็ใช้ได้เอง) */}
              {tunnelError && (
                <div className="form-error">
                  Unable to check if any Tunnel is using this Security Profile ({tunnelError}) - Delete and rename are disabled until data is retrieved
                </div>
              )}
              <section className="ikev2-object-section security-profile-section">
                <div className="ikev2-section-heading"><div><h3>Security Profile</h3></div></div>
                <div className="command-output-title">
                  <Edit_Result
                    featureName="Security Profile"
                    selectedLabel={selectedProfile?.name || ""}
                    extraWarning={
                      isBound
                        ? boundMessage
                        : isBrownfield
                          ? describeRemoval(selectedProfile.real)
                          : "Delete all associated IKEv2/IPsec objects in a single command"
                    }
                    canEdit={!!selectedName}
                    canDelete={!!selectedName && !isBound && !bindingUnknown}
                    showDeleteConfirm={showDeleteConfirm}
                    deleting={deleting}
                    deleteError={deleteError} onDismissDeleteError={() => setDeleteError("")}
                    onNew={() => setFormMode("create")}
                    onEditClick={() => setFormMode("edit")}
                    onOpenDeleteConfirm={() => setShowDeleteConfirm(true)}
                    onCancelDelete={() => setShowDeleteConfirm(false)}
                    onConfirmDelete={() => handleConfirmDelete(selectedProfile)}
                    refreshing={loading}
                    onRefresh={refetch}
                  />
                </div>

                {profiles.length === 0 ? (
                  <div className="config-placeholder">No Security Profile configured</div>
                ) : (
                  <table className="data-table">
                    <thead>
                      <tr>
                        {/* (bug 95) ตัด IPsec Encryption/Integrity/PFS ออก - เดิมโชว์เฉพาะฝั่ง IPsec
                            ทำให้ผู้ใช้เข้าใจว่านั่นคือ algorithm ทั้งหมดของ profile ทั้งที่ยังมีชั้น
                            IKEv2 ที่สำคัญไม่แพ้กันแต่ไม่ได้โชว์ - ข้อมูลครึ่งเดียวหลอกกว่าไม่มีข้อมูล
                            ผู้ใช้ตัดสินใจให้เหลือแค่ 3 คอลัมน์ที่ระบุตัว profile ได้ ส่วน algorithm
                            ทั้งสองชั้นไปดูตอนกดแก้ไข (bug 92 ทำให้ฟอร์มแก้ไขโชว์ค่าจริงแล้ว) */}
                        <th>Name</th>
                        <th>Peer IP</th>
                        <th>Mode</th>
                      </tr>
                    </thead>
                    <tbody>
                      {profiles.map((profile, index) => (
                        <tr
                          key={`${profile.name}-${index}`}
                          className={`row-clickable ${profile.name === selectedName ? "row-selected" : ""}`}
                          onClick={() => setSelectedName(profile.name === selectedName ? null : profile.name)}
                        >
                          <td>{profile.name || "-"}</td>
                          <td>{profile.peerIp || "-"}</td>
                          <td>{profile.mode}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </section>
            </div>
          )}

          {activeTab !== "profile" && ciscoIkev2Objects && (
            <div role="tabpanel" id={`tabpanel-${activeTab}`} aria-labelledby={`tab-${activeTab}`}>
              <CiscoIkev2Tables
                devId={devId}
                objects={ciscoIkev2Objects}
                refetch={refetch}
                refreshing={loading}
                view={null}
                setView={setCiscoIkev2View}
                section={activeTab}
              />
            </div>
          )}
        </>
      )}
    </div>
  );
}
