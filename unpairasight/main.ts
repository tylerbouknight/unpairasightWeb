import { Plugin, Modal, App, Notice, PluginSettingTab, Setting } from "obsidian";
import * as crypto from "crypto";
import { extractFrontmatter, hasMatchingTag } from './utils';



interface UnPairasightSettings {
    passwordSet: boolean;
    purged: boolean;
    passwordHash?: string;
    tagsToEncrypt?: string[];
    tagsToSkip?: string[];
  }
  
  

// Main Plugin Class
export default class UnPairasightPlugin extends Plugin {
  password: string | null = null;
  isFirstRun: boolean = true;
  settings: UnPairasightSettings;
  readonly SIGNATURE: string = "[ENCRYPTED]";

  // Lifecycle Methods
  async onload() {
    await this.loadSettings();
    this.registerCommands();
    this.handleWorkspaceEvents();
    this.addSettingTab(new UnPairasightSettingTab(this.app, this));

  }

  handleWorkspaceEvents() {
    this.app.workspace.onLayoutReady(() => {
      if (this.settings.passwordSet) {
        new PasswordModal(this.app, this, false).open();
      } else {
        new PasswordModal(this.app, this, true).open();
      }
    });

    this.app.workspace.on("quit", async () => {
      if (this.password) {
        await this.encryptVault(this.password);
      }
    });
  }

  // Settings Management
  async loadSettings() {
    this.settings = Object.assign(
      {
        passwordSet: false,
        purged: false,
        tagsToEncrypt: [],
        tagsToSkip: []
      },
      await this.loadData()
    );
  }
  
  async saveSettings() {
    await this.saveData(this.settings);
  }
  

  setPassword(password: string) {
    this.password = password;
  }
  async registerCommands() {
    // Encrypt Vault Command
    this.addCommand({
      id: "encrypt-vault",
      name: "Encrypt Vault",
      callback: () => this.promptPasswordIfNeededThenEncrypt(),
    });

    // Decrypt Vault Command
    this.addCommand({
        id: 'decrypt-vault',
        name: 'Decrypt Vault',
        callback: () => {
          // Open the PasswordModal for decryption
          new PasswordModal(this.app, this, false, true).open();
        },
      }); 

    // Purge Password Command
    this.addCommand({
      id: "purge-password",
      name: "Purge Password",
      callback: () => this.purgePassword(),
    });
  }

  promptPasswordIfNeededThenEncrypt() {
    if (this.password) {
      this.encryptVault(this.password);
    } else {
      new PasswordModal(this.app, this, false).open();
    }
  }

  purgePassword() {
    this.password = null;
    this.settings.passwordSet = false;
    this.settings.purged = true;
    this.saveSettings();
    new Notice("Password successfully purged.");
  }

  
  // Encryption & Decryption Logic
  async encryptVault(password: string) {
    const fileCache = this.app.vault.getMarkdownFiles();
    const tagsToEncrypt = this.settings.tagsToEncrypt || []; 
    const tagsToSkip = this.settings.tagsToSkip || [];
    
    const encryptPromises = fileCache.map(async file => {
      let fileContent = await this.app.vault.read(file);
      
      if (fileContent.startsWith(this.SIGNATURE)) return;
  
      const frontmatter = extractFrontmatter(fileContent);
      
      if (hasMatchingTag(frontmatter, tagsToSkip)) {
        return; // Skip encryption for these files
      }
  
      if (tagsToEncrypt.length > 0 && !hasMatchingTag(frontmatter, tagsToEncrypt)) {
        return; // Only encrypt files that have matching tags
      }
  
      const encryptedContent = this.encrypt(fileContent, password);
      await this.app.vault.modify(file, encryptedContent);
    });
  
    await Promise.all(encryptPromises);
  }
  
  
  
  
  async decryptVault(password: string) {
    const fileCache = this.app.vault.getMarkdownFiles();
    const tagsToEncrypt = this.settings.tagsToEncrypt || []; 
    const tagsToSkip = this.settings.tagsToSkip || [];

    const decryptPromises = fileCache.map(async file => {
      let fileContent = await this.app.vault.read(file);
      
      if (!fileContent.startsWith(this.SIGNATURE)) return;
  
      const frontmatter = extractFrontmatter(fileContent);
      
      if (hasMatchingTag(frontmatter, tagsToSkip)) {
        return; // Skip decryption for these files
      }
  
      if (tagsToEncrypt.length > 0 && !hasMatchingTag(frontmatter, tagsToEncrypt)) {
        return; // Only decrypt files that have matching tags
      }
  
      const decryptedContent = this.decrypt(fileContent, password);
      await this.app.vault.modify(file, decryptedContent);
    });
  
    await Promise.all(decryptPromises);
  }
  
  
  
  

  encrypt(text: string, password: string): string {
    const iv = crypto.randomBytes(16);
    const key = crypto.scryptSync(password, 'salt', 32);
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    encrypted = this.SIGNATURE + iv.toString('hex') + encrypted;
  
    return encrypted;
  }
  
  decrypt(text: string, password: string): string {
    const key = crypto.scryptSync(password, 'salt', 32);
    if (text.startsWith(this.SIGNATURE)) {
      text = text.substring(this.SIGNATURE.length);
    } else {
      return text;
    }
  
    const iv = Buffer.from(text.substring(0, 32), 'hex');
    text = text.substring(32);
  
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    let decrypted = decipher.update(text, "hex", "utf8");
    decrypted += decipher.final("utf8");
  
    return decrypted;
  }
  
  hashPassword(password: string): string {
    const hash = crypto.createHash("sha256");
    hash.update(password);
    return hash.digest("hex");
  }

  verifyPassword(inputPassword: string, storedHash: string): boolean {
    return this.hashPassword(inputPassword) === storedHash;
  }
}

// Modal Class for Password Management
class PasswordModal extends Modal {
  plugin: UnPairasightPlugin;
  isFirstRun: boolean;

  constructor(app: App, plugin: UnPairasightPlugin, isFirstRun: boolean, isDecrypt: boolean = false) {
    super(app);
    this.plugin = plugin;
    this.isFirstRun = isFirstRun;
  }

  onOpen() {
    this.createUI();
  }

  createUI() {
    let { contentEl } = this;
    const title = this.isFirstRun
      ? "Create Password to Lock Vault"
      : "Enter Password to Unlock Vault";
    contentEl.createEl("h2", { text: title });

    const passwordInput = contentEl.createEl("input", { type: "password" });
    const unlockButton = contentEl.createEl("button", { text: "Unlock" });

    unlockButton.addEventListener("click", () =>
      this.handleUnlock(passwordInput.value),
    );
  }

  handleUnlock(password: string, isDecrypt: boolean = false) {
    if (isDecrypt) {
      if (this.plugin.verifyPassword(password, this.plugin.settings.passwordHash!)) {
        this.plugin.decryptVault(password).catch(err => {
          console.error("Failed to decrypt vault:", err);
        });
        this.close();
      } else {
        // Show an error message or retry logic
        console.error("Incorrect password");
      }
    } else {
      this.plugin.setPassword(password);
      this.plugin.decryptVault(password).catch(err => {
        console.error("Failed to decrypt vault:", err);
      });
      this.close();
    }
  }

  onClose() {
    let { contentEl } = this;
    contentEl.empty();
  }
}
class UnPairasightSettingTab extends PluginSettingTab {
    plugin: UnPairasightPlugin;
  
    constructor(app: App, plugin: UnPairasightPlugin) {
      super(app, plugin);
      this.plugin = plugin;
    }
  
    display(): void {
      const { containerEl } = this;
  
      containerEl.empty();
  
      new Setting(containerEl)
        .setName('Tags to Encrypt')
        .setDesc('Comma-separated list of tags you want to encrypt')
        .addText(text => text
          .setValue(this.plugin.settings.tagsToEncrypt?.join(', ') || '')
          .onChange(async (value) => {
            this.plugin.settings.tagsToEncrypt = value.split(',').map(tag => tag.trim());
            await this.plugin.saveSettings();
          }));
          
      new Setting(containerEl)
        .setName('Tags to Skip')
        .setDesc('Comma-separated list of tags you don\'t want to encrypt')
        .addText(text => text
          .setValue(this.plugin.settings.tagsToSkip?.join(', ') || '')
          .onChange(async (value) => {
            this.plugin.settings.tagsToSkip = value.split(',').map(tag => tag.trim());
            await this.plugin.saveSettings();
          }));
    }
  }