/** Messages exchanged between the extension and a classifier worker. */
export interface InitMessage {
  readonly type: 'init';
  readonly modelDir: string;
  readonly maxLength?: number;
}

export interface ScoreMessage {
  readonly type: 'score';
  readonly id: number;
  readonly code: string;
}

export interface CloseMessage {
  readonly type: 'close';
}

export type WorkerRequest = InitMessage | ScoreMessage | CloseMessage;

export interface ReadyMessage {
  readonly type: 'ready';
  readonly maxLength: number;
}

export interface ResultMessage {
  readonly type: 'result';
  readonly id: number;
  readonly vulnerable: number;
  readonly safe: number;
}

export interface ErrorMessage {
  readonly type: 'error';
  readonly id?: number;
  readonly message: string;
  readonly kind: string;
}

export interface ClosedMessage {
  readonly type: 'closed';
}

export type WorkerResponse = ReadyMessage | ResultMessage | ErrorMessage | ClosedMessage;