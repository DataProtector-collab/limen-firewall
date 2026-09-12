import { useFirewall } from "@/lib/firewall/store";
import { t } from "@/lib/i18n";

export function useT() {
  const language = useFirewall((s) => s.settings.language);
  return (key: string, vars?: Record<string, string | number>) => t(language, key, vars);
}
