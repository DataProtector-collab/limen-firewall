export function endpoint(ip: string | undefined, port: number): string {
  const address = ip || "*";
  return (address.includes(":") ? "[" + address + "]" : address) + ":" + port;
}
