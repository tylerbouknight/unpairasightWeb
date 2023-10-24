import { Plugin, Notice} from "obsidian";
import { extractFrontmatter, hasMatchingTag } from './utils';
import * as Encryption from "./encryption";
import { PasswordModal, UnPairasightSettingTab } from './ui'



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
  
      const encryptedContent = Encryption.encrypt(fileContent, password);  // Using the modularized function
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
  
      const decryptedContent = Encryption.decrypt(fileContent, password);  // Using the modularized function
      await this.app.vault.modify(file, decryptedContent);
    });
  
    await Promise.all(decryptPromises);
  }
}