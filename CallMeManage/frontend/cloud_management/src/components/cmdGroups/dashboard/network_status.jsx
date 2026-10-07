import DismissibleError from "../../DismissibleError";
import { useMemo } from "react";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { Reload_Result } from "../../commandResult/reload_command_result";
import { displayStaticRouteDistance } from "../../../utils/staticRouteDistance";
import { routingStatusRoutes } from "../../../utils/routingStatusDisplay";

// แปลง input ให้กลายเป็น array ไม่ว่าจะกรอกข้อมูลเข้ามายังไง
function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// ดึง routing ทุกตัวของ juniper ออกมา
function extractJuniperAllRoutes(payload) {
  const tables = ensureArray(payload?.["route-information"]?.["route-table"]);
  const routes = [];
  for (const table of tables) {
    for (const rt of ensureArray(table?.rt)) {
      for (const entry of ensureArray(rt?.["rt-entry"])) {
        const nh = ensureArray(entry?.nh)[0] || {};
        routes.push({
          prefix: rt?.["rt-destination"] || "",
          protocol: entry?.["protocol-name"] || "",
          nextHop: nh?.to || "",
          iface: nh?.via || "",
          distance: entry?.preference || "",
          metric: entry?.metric || "",
        });
      }
    }
  }
  return routes;
}

// VRP query staticrt/srRoutes ไม่ใช่ full RIB; ทุกแถวจึงเป็น Static ตาม
// ขอบเขตข้อมูลที่ translator อ่านจริง ไม่เดา protocol อื่นที่ไม่ได้รับมา.
function extractHuaweiRoutes(payload) {
  const entries = ensureArray(payload?.data?.staticrt?.staticrtbase?.srRoutes?.srRoute);
  return entries.map((entry) => ({
    prefix: entry?.prefix !== undefined && entry?.maskLength !== undefined
      ? `${entry.prefix}/${entry.maskLength}` : entry?.prefix || "",
    protocol: "Static",
    nextHop: entry?.nexthop || "",
    iface: entry?.ifName || "",
    distance: entry?.preference || "",
    metric: entry?.cost || "",
  }));
}

// ดึง routing ทุกตัวของอุปกรณ์ออกมา
function extractAllRoutes(payload, vendor) {
  if (vendor === "huawei") {
    try {
      return extractHuaweiRoutes(payload);
    } catch {
      return null;
    }
  }
  if (vendor === "juniper") {
    try {
      return extractJuniperAllRoutes(payload);
    } catch {
      return null;
    }
  }
  try {
    const routingState = payload?.data?.["routing-state"];
    const instances = ensureArray(routingState?.["routing-instance"]);
    const routes = [];
    for (const instance of instances) {
      const ribs = ensureArray(instance?.ribs?.rib);
      for (const rib of ribs) {
        const entries = ensureArray(rib?.routes?.route);
        for (const route of entries) {
          const nextHop = route?.["next-hop"] || {};
          routes.push({
            prefix: route?.["destination-prefix"] || "",
            protocol: route?.["source-protocol"] || "",
            nextHop: nextHop?.["next-hop-address"] || "",
            iface: nextHop?.["outgoing-interface"] || "",
            distance: route?.["route-preference"] || "",
            metric: route?.["metric"] || "",
          });
        }
      }
    }
    return routes;
  } catch {
    return null;
  }
}

// ส่งออก Function ที่จะให้แสดงผล routing บนหน้าเว็บ
export default function NetworkStatus({ devId }) {
  // เรียกใช้ hooks/getDeviceInformation.js เพื่อดึงข้อมูลอุปกรณ์มาแสดงผล
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_routing_table");
  const payload = data?.normalized ? data.result?.payload : null;
  const vendor = data?.result?.vendor;

  // ห่อข้อมูล routing ด้วย useMemo เพื่อกัน re-compute ทุกครั้งที่ re-render
  const routes = useMemo(
    () => {
      if (!payload) return null;
      const extracted = extractAllRoutes(payload, vendor);
      return extracted === null ? null : routingStatusRoutes(extracted, vendor);
    },
    [payload, vendor]
  );

  // ถ้ามีการโหลดและยังไม่พบข้อมูลให้แสดงผลว่า "กำลังดึงข้อมูลอยู่"
  if (loading && !data) return <div className="center-loading">Fetching routing table data...</div>;

  return (
    <div className="command-output">
      <div className="command-output-title">
        {/* แสดงผลปุ่ม refresh */}
        <Reload_Result loading={loading} onRefresh={refetch}/>
      </div>

      {/* เงื่อนไขรองรับการทำงาน error */}
      {error && <DismissibleError message={error} onDismiss={clearError} />}
      
      {/* เงื่อนไขการแสดงผลการดึงข้อมูล route */}
      {routes === null ? (
        // ถ้ามีข้อมูลอยู่จริงแต่แปลไม่ได้ จะส่งค่าเป็น null ทำให้แสดงผลแบบนี้
        data && (
          <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
        )
      ) : routes.length === 0 ? (
        // ถ้าข้อมูลมีความยาวเป็น 0 จะแสดงผลข้อมูลนี้
        <div className="config-placeholder">No routes in table</div>
      ) : (
        // ถ้ามีข้อมูลมากกว่า 0 จะแสดงผลเป็นตาราง
        <table className="data-table">
          <thead>
            <tr>
              <th>Destination</th>
              <th>Protocol</th>
              <th>Next Hop</th>
              <th>Exit Interface</th>
              <th>Distance</th>
              <th>Metric</th>
            </tr>
          </thead>
          <tbody>
            {routes.map((route, index) => (
              <tr key={`${route.prefix}-${index}`}>
                <td>{route.prefix}</td>
                <td>{route.protocol || "-"}</td>
                <td>{route.nextHop || "-"}</td>
                <td>{route.iface || "-"}</td>
                <td>
                  {(route.protocol || "").toLowerCase() === "static"
                    ? displayStaticRouteDistance(route.distance, vendor)
                    : route.distance || "-"}
                </td>
                <td>{route.metric || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
