import { encode, decode } from "https://deno.land/std@0.147.0/encoding/hex.ts";
import { User, Token } from "../common/user.ts";

// not SRP
// this class have too many responsibility
class Authentication {
  private users: Map<string, User> = new Map();
  private encoder = new TextEncoder();
  private decoder = new TextDecoder();

  public getUser(username: string): User | undefined {
    return this.users.get(username);
  }

  public registerUser(user: User): User {
    this.users.set(user.username, user);
    return user;
  }

  private encodeText(text: string): Token {
    const binaryForm = this.encoder.encode(text);
    const uintHex = encode(binaryForm);
    return this.decoder.decode(uintHex);
  }

  private decodeText(token: Token): string {
    const binaryForm = this.encoder.encode(token);
    const uintText = decode(binaryForm);
    return this.decoder.decode(uintText);
  }

  private createToken(user: User): Token {
    const material = `${user.username}:${user.password}`;
    return this.encodeText(material);
  }

  private parseToken(decodedToken: string): [string, string] {
    const [username, password] = decodedToken.split(":");
    return [username, password];
  }

  private getUsernameFromToken(token: Token): string {
    const decodedToken = this.decodeText(token);
    const [username] = this.parseToken(decodedToken);
    return username;
  }

  public authenticate(username: string, password: string): Token {
    const user = this.getUser(username);
    if (user && user.username === password) {
      return this.createToken(user);
    }
    throw new Error("invalid user or password");
  }

  public validateToken(token: string): User {
    const username = this.getUsernameFromToken(token);
    const user = this.getUser(username);
    if (!user) throw new Error("invalid user");
    const validToken = this.createToken(user);
    const isGivenTokenValid = token === validToken;
    if (!isGivenTokenValid) throw new Error("invalid token");
    return user;
  }
}

class Program {
  run() {
    console.log("SOLID - NOT SRP");
    const authentication = new Authentication();

    // register user
    const newUser = new User("billy", "secret");
    authentication.registerUser(newUser);

    // login (generate token)
    const token = authentication.authenticate("billy", "secret");

    // validate token
    const validatedUser = authentication.validateToken(token);

    console.log(validatedUser);
    console.log();
  }
}

new Program().run();
