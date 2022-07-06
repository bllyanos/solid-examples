import { encode, decode } from "https://deno.land/std@0.147.0/encoding/hex.ts";
import { User, Token } from "../common/user.ts";

// SRP
// (a bit abstraction)
interface Repository<T, K> {
  get(key: K): T;
  getAll(): T[];
  save(item: T): T;
  remove(key: K): T;
}

interface Encoder<R, E> {
  encode(raw: R): E;
  decode(encoded: E): R;
}

interface Authenticator {
  authenticate(username: string, password: string): Token;
  validateToken(token: string): User;
}

// responsible for managing user data (storing, etc)
class InMemoryUserRepository implements Repository<User, string> {
  private users: Map<string, User> = new Map();

  get(key: string): User {
    const user = this.users.get(key);
    if (!user) throw new Error("user not found");
    return user;
  }

  getAll(): User[] {
    const users = new Array<User>(this.users.size);
    let index = 0;
    for (const user of this.users.values()) {
      users[index++] = user;
    }
    return users;
  }

  save(item: User): User {
    this.users.set(item.username, item);
    return item;
  }

  remove(key: string): User {
    const user = this.users.get(key);
    if (!user) throw new Error("user not found");
    this.users.delete(key);
    return user;
  }
}

// responsible for hex encoding & decoding
class Hexer implements Encoder<string, Token> {
  private encoder = new TextEncoder();
  private decoder = new TextDecoder();

  public encode(text: string): Token {
    const binaryForm = this.encoder.encode(text);
    const uintHex = encode(binaryForm);
    return this.decoder.decode(uintHex);
  }

  public decode(token: Token): string {
    const binaryForm = this.encoder.encode(token);
    const uintText = decode(binaryForm);
    return this.decoder.decode(uintText);
  }
}

// responsible for authenticating by token
class BasicAuthenticator implements Authenticator {
  constructor(
    private userRepository: Repository<User, string>,
    private encoder: Encoder<string, Token>
  ) {}

  private createToken(user: User): Token {
    const material = `${user.username}:${user.password}`;
    return this.encoder.encode(material);
  }

  private parseToken(decodedToken: string): [string, string] {
    const [username, password] = decodedToken.split(":");
    return [username, password];
  }

  private getUsernameFromToken(token: Token): string {
    const decodedToken = this.encoder.decode(token);
    const [username] = this.parseToken(decodedToken);
    return username;
  }

  public authenticate(username: string, password: string): Token {
    const user = this.userRepository.get(username);
    if (user && user.username === password) {
      return this.createToken(user);
    }
    throw new Error("invalid user or password");
  }

  public validateToken(token: string): User {
    const username = this.getUsernameFromToken(token);
    const user = this.userRepository.get(username);
    if (!user) throw new Error("invalid user");
    const validToken = this.createToken(user);
    const isGivenTokenValid = token === validToken;
    if (!isGivenTokenValid) throw new Error("invalid token");
    return user;
  }
}

class Program {
  run() {
    console.log("SOLID - SRP");
    const userRepository: Repository<User, string> =
      new InMemoryUserRepository();
    const hexEncoder: Encoder<string, Token> = new Hexer();
    const authenticator: Authenticator = new BasicAuthenticator(
      userRepository,
      hexEncoder
    );

    // register user
    const newUser = new User("billy", "secret");
    userRepository.save(newUser);

    // login (generate token)
    const token = authenticator.authenticate("billy", "secret");

    // validate token
    const validatedUser = authenticator.validateToken(token);

    console.log(validatedUser);
    console.log();
  }
}

new Program().run();
