import { useState } from "react";

type PortResult = {
  port: number;
  service: string;
  risk: string;
  impact: string;
  recommendation: string;
};

type Props = {
  data: PortResult;
};

export function PortResultCard({ data }: Props) {
  const [open, setOpen] = useState(false);

  return (
    <div className="border rounded p-3 mb-3 bg-dark text-light">
      <div
        style={{ cursor: "pointer" }}
        onClick={() => setOpen(!open)}
      >
        <strong>
          {open ? "▼" : "▶"} Porta {data.port} ({data.service}) – {data.risk}
        </strong>
      </div>

      {open && (
        <div className="mt-3">
          <p><strong>Impacto:</strong> {data.impact}</p>
          <p><strong>Recomendação:</strong> {data.recommendation}</p>
        </div>
      )}
    </div>
  );
}