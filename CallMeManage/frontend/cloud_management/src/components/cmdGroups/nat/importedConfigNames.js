/**
 * Add stable display-only names to Cisco NAT rows that exist on the device but
 * have no Device_Config_Object. Reading a device must never write to the DB;
 * the generated name is registered only if the user later saves the row.
 */
export function buildImportedNameMap(rows, trackedNames, keyOf, prefix) {
  const result = {};
  const usedNames = new Set(
    (rows || []).map((row) => trackedNames?.[keyOf(row)]).filter(Boolean),
  );
  let sequence = 1;

  for (const row of rows || []) {
    const key = keyOf(row);
    const trackedName = trackedNames?.[key];
    if (trackedName) {
      result[key] = trackedName;
      continue;
    }

    let generated;
    do {
      generated = `${prefix}-${sequence}`;
      sequence += 1;
    } while (usedNames.has(generated));
    usedNames.add(generated);
    result[key] = generated;
  }

  return result;
}
