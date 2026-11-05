// The report PDF layout is shared with the dashboard: frontend/src/utils/reportPdf.js (jsPDF).
declare module '*/utils/reportPdf.js' {
  export function buildPdf(data: unknown, reportType: string): { output(type: 'arraybuffer'): ArrayBuffer }
}
