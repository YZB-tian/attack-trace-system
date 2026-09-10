import { Activity, Cable, Crosshair, Database, FileText, Globe, Network, RadioTower, TerminalSquare, UserRound } from "lucide-react";
import type { GraphNode } from "../types/contracts";
import { formatNodeDisplay } from "./node-display";
import "./chain-preview.css";

const icons: Record<GraphNode["type"], typeof Network> = {
  host: TerminalSquare, user: UserRound, process: Activity, file: FileText,
  ip: Network, domain: Globe, session: Cable, c2: RadioTower,
  technique: Crosshair, other: Database,
};

export default function ChainPreview({ nodes }: { nodes: GraphNode[] }) {
  if (!nodes.length) return <p className="chain-entity-empty">暂无攻击图实体</p>;
  const visibleNodes = nodes.slice(0, 4);
  return <div className="chain-entity-preview">
    <ul className="chain-entity-list" aria-label="攻击图实体预览">
      {visibleNodes.map((node) => {
        const display = formatNodeDisplay(node);
        const Icon = icons[node.type];
        return <li className={`chain-entity type-${node.type}`} key={node.id} title={`${display.fullLabel}\n原始标签：${node.label}\n节点 ID：${node.id}`}>
          <div className="chain-entity-heading"><Icon size={17} aria-hidden="true" /><span className="chain-entity-type">[{display.typeLabel}]</span></div>
          <strong className="chain-entity-title">{display.title}</strong>
          {display.summary && <span className="chain-entity-summary">{display.summary}</span>}
        </li>;
      })}
    </ul>
    {nodes.length > visibleNodes.length && <p className="chain-entity-count">展示 {visibleNodes.length} / {nodes.length} 个实体</p>}
  </div>;
}
