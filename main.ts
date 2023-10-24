import { Plugin, Modal, App, Notice } from "obsidian";
import * as crypto from "crypto";

export default class UnPairasightPlugin extends Plugin {
	password: string | null = null;
	isFirstRun: boolean = true;
	settings: UnPairasightSettings;
	readonly SIGNATURE: string = "[ENCRYPTED]";

	async onload() {
		await this.loadSettings();
		this.registerCommands();

		this.app.workspace.onLayoutReady(() => {
			new PasswordModal(this.app, this, !this.settings.passwordSet).open();
		});

		this.app.workspace.on("quit", async () => {
			if (this.password) {
				await this.encryptVault(this.password);
			}
		});
	}
	async registerCommands() {
		this.addCommand({
			id: "encrypt-vault",
			name: "Encrypt Vault",
			callback: () => {
				if (this.password) {
					this.encryptVault(this.password);
				} else {
					new PasswordModal(this.app, this, false).open(); // Open password dialog if not set
				}
			},
		});

		this.addCommand({
			id: "purge-password",
			name: "Purge Password",
			callback: async () => {
				// Reset settings and remove password
				this.password = null;
				this.settings.passwordSet = false;
				this.settings.purged = true;
				await this.saveSettings();

				// Notify the user
				new Notice("Password purged and vault decrypted successfully.");
			},
		});
	}

	async loadSettings() {
		this.settings = Object.assign(
			{
				passwordSet: false,
				purged: false,
			},
			await this.loadData(),
		);
	}
	async saveSettings() {
		await this.saveData(this.settings);
	}

	setPassword(password: string) {
		this.password = password;
		this.settings.passwordSet = true;
		this.saveSettings();
	}

	async encryptVault(password: string) {
		const fileCache = this.app.vault.getMarkdownFiles();
		for (const file of fileCache) {
			const fileContent = await this.app.vault.read(file);
			const encryptedContent = this.encrypt(fileContent, password);
			console.log(
				"Encrypting:",
				crypto.createHash("sha256").update(password).digest("hex"),
				fileContent.slice(0, 10),
			); // First 10 chars

			await this.app.vault.modify(file, encryptedContent);
		}
	}

	async decryptVault(password: string) {
		const fileCache = this.app.vault.getMarkdownFiles();
		for (const file of fileCache) {
			const fileContent = await this.app.vault.read(file);
			const decryptedContent = this.decrypt(fileContent, password);
			console.log(
				"Decrypting:",
				crypto.createHash("sha256").update(password).digest("hex"),
				fileContent.slice(0, 10),
			); // First 10 chars

			await this.app.vault.modify(file, decryptedContent);
		}
	}

	encrypt(text: string, password: string): string {
		const cipher = crypto.createCipher("aes-256-cbc", password);
		let encrypted = cipher.update(text, "utf8", "hex");
		encrypted += cipher.final("hex");
		encrypted = this.SIGNATURE + encrypted;

		return encrypted;
	}

	decrypt(text: string, password: string): string {
		if (text.startsWith(this.SIGNATURE)) {
			// Remove the signature
			text = text.substring(this.SIGNATURE.length);
		} else {
			// If the signature is not found, return the original text as-is
			return text;
		}
		const decipher = crypto.createDecipher("aes-256-cbc", password);
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

class PasswordModal extends Modal {
	plugin: UnPairasightPlugin;
	isFirstRun: boolean;

	constructor(app: App, plugin: UnPairasightPlugin, isFirstRun: boolean) {
		super(app);
		this.plugin = plugin;
		this.isFirstRun = isFirstRun;
	}

	onOpen() {
		let { contentEl } = this;

		if (this.isFirstRun) {
			contentEl.createEl("h2", { text: "Create Password to Lock Vault" });
		} else {
			contentEl.createEl("h2", { text: "Enter Password to Unlock Vault" });
		}

		const passwordInput = contentEl.createEl("input", { type: "password" });
		const unlockButton = contentEl.createEl("button", { text: "Unlock" });

		unlockButton.addEventListener("click", () => {
			this.plugin.setPassword(passwordInput.value);
			this.plugin.password = passwordInput.value;
			this.decryptVault();
			this.close();
		});
	}

	async decryptVault() {
		if (this.plugin.password) {
			await this.plugin.decryptVault(this.plugin.password);
		}
	}

	onClose() {
		let { contentEl } = this;
		contentEl.empty();
	}
}
interface UnPairasightSettings {
	passwordSet: boolean;
	purged: boolean;
}
